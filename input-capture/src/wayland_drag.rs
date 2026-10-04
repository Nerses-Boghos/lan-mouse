//! The files of a drag that reaches a screen edge leading to another device
//! (Wayland).
//!
//! Wayland shows a drag only to the surface under the pointer. So along
//! every such edge, an invisible strip one pixel wide (a layer-shell surface
//! above everything) is the surface under the pointer when a drag gets
//! there: it learns which files are dragged (`text/uri-list`) on the way
//! across. A drag that ends on the strip (released at the edge, e.g. when
//! the pointer was handed to the other device) is accepted as a copy and
//! ends without effect for the source.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    io::Read,
    os::{
        fd::{AsFd, FromRawFd, OwnedFd},
        unix::ffi::OsStringExt,
    },
    path::PathBuf,
    sync::{
        Mutex, OnceLock,
        mpsc::{Receiver, Sender, channel},
    },
    time::{Duration, Instant},
};

use wayland_client::{
    Connection, Dispatch, EventQueue, Proxy, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{
        wl_buffer::WlBuffer,
        wl_compositor::WlCompositor,
        wl_data_device::{self, WlDataDevice},
        wl_data_device_manager::{DndAction, WlDataDeviceManager},
        wl_data_offer::{self, WlDataOffer},
        wl_output::{self, WlOutput},
        wl_pointer::{self, WlPointer},
        wl_registry,
        wl_seat::{self, WlSeat},
        wl_shm::{self, WlShm},
        wl_shm_pool::WlShmPool,
        wl_surface::WlSurface,
    },
};
use wayland_protocols::wp::cursor_shape::v1::client::{
    wp_cursor_shape_device_v1::{Shape, WpCursorShapeDeviceV1},
    wp_cursor_shape_manager_v1::WpCursorShapeManagerV1,
};
use wayland_protocols_wlr::layer_shell::v1::client::{
    zwlr_layer_shell_v1::{Layer, ZwlrLayerShellV1},
    zwlr_layer_surface_v1::{self, Anchor, KeyboardInteractivity, ZwlrLayerSurfaceV1},
};

use crate::Position;

const URI_LIST: &str = "text/uri-list";
/// A drag that left the strip (the pointer went to the other device, or
/// back) still counts for this long.
const REMEMBER: Duration = Duration::from_secs(3);

/// The last drag seen at an edge.
struct Seen {
    /// counts drags, so a slow read can't update a later one
    generation: u64,
    /// the dragged files, once read (`None` while reading, or not files)
    files: Option<Vec<PathBuf>>,
    /// still reading the files from the drag's source
    reading: bool,
    /// when the drag left the strip; `None` while it is on it
    left: Option<Instant>,
}

static SEEN: Mutex<Seen> = Mutex::new(Seen {
    generation: 0,
    files: None,
    reading: false,
    left: None,
});
static EDGES: OnceLock<Mutex<Sender<Vec<Position>>>> = OnceLock::new();

/// The files of a drag at (or just through) an edge to another device.
pub fn current_drag() -> Option<Vec<PathBuf>> {
    let seen = SEEN.lock().ok()?;
    let recent = seen.left.is_none_or(|left| left.elapsed() < REMEMBER);
    seen.files
        .clone()
        .filter(|files| recent && !files.is_empty())
}

/// Whether a drag of files is at (or just through) an edge, but its files
/// are still being read from its source (a fast crossing can be quicker).
pub fn drag_pending() -> bool {
    SEEN.lock()
        .is_ok_and(|seen| seen.reading && seen.left.is_none_or(|left| left.elapsed() < REMEMBER))
}

/// Watch the screen edges at `edges` (the sides other devices are on) for
/// drags. Starts the watcher on first use.
pub fn watch_edges(edges: Vec<Position>) {
    let sender = EDGES.get_or_init(|| {
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("drag-strips".into())
            .spawn(move || {
                if let Err(e) = run(rx) {
                    log::warn!("can't watch the screen edges for dragged files: {e}");
                }
            })
            .expect("spawn thread");
        Mutex::new(tx)
    });
    if let Ok(sender) = sender.lock() {
        let _ = sender.send(edges);
    }
}

/// Paths of the `file://` URIs in a `text/uri-list`.
fn parse_uri_list(list: &str) -> Vec<PathBuf> {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|uri| uri.strip_prefix("file://"))
        // file:///path or file://host/path: the path starts at the first '/'
        .filter_map(|rest| rest.find('/').map(|slash| &rest[slash..]))
        .filter_map(percent_decode)
        .map(|bytes| PathBuf::from(OsString::from_vec(bytes)))
        .collect()
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

#[derive(Default)]
struct Output {
    /// position and logical size in the global space
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    scale: i32,
}

struct Strip {
    surface: WlSurface,
    layer: ZwlrLayerSurfaceV1,
    buffer: Option<WlBuffer>,
}

struct State {
    compositor: WlCompositor,
    layer_shell: ZwlrLayerShellV1,
    shm: WlShm,
    cursor_shapes: Option<WpCursorShapeManagerV1>,
    cursor: Option<WpCursorShapeDeviceV1>,
    outputs: HashMap<u32, (WlOutput, Output)>,
    strips: Vec<Strip>,
    edges: Vec<Position>,
    /// mime types of each data offer
    offers: HashMap<wayland_client::backend::ObjectId, Vec<String>>,
    /// the offer of the drag on a strip, if it carries files
    dragging: Option<WlDataOffer>,
    connection: Connection,
}

fn run(edges: Receiver<Vec<Position>>) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::connect_to_env()?;
    let (globals, mut queue): (_, EventQueue<State>) = registry_queue_init(&connection)?;
    let qh = queue.handle();
    let compositor: WlCompositor = globals.bind(&qh, 4..=6, ())?;
    let layer_shell: ZwlrLayerShellV1 = globals.bind(&qh, 1..=4, ())?;
    let shm: WlShm = globals.bind(&qh, 1..=1, ())?;
    let seat: WlSeat = globals.bind(&qh, 1..=7, ())?;
    let manager: WlDataDeviceManager = globals.bind(&qh, 3..=3, ())?;
    let cursor_shapes: Option<WpCursorShapeManagerV1> = globals.bind(&qh, 1..=1, ()).ok();
    let outputs = globals.contents().with_list(|list| {
        list.iter()
            .filter(|g| g.interface == "wl_output")
            .map(|g| (g.name, g.version))
            .collect::<Vec<_>>()
    });
    let mut state = State {
        compositor,
        layer_shell,
        shm,
        cursor_shapes,
        cursor: None,
        outputs: HashMap::new(),
        strips: vec![],
        edges: vec![],
        offers: HashMap::new(),
        dragging: None,
        connection: connection.clone(),
    };
    for (name, version) in outputs {
        let output: WlOutput = globals.registry().bind(name, version.min(4), &qh, name);
        state.outputs.insert(name, (output, Output::default()));
    }
    manager.get_data_device(&seat, &qh, ());
    queue.roundtrip(&mut state)?;

    loop {
        // the edges in use changed (devices added, moved, removed)
        let mut changed = None;
        while let Ok(edges) = edges.try_recv() {
            changed = Some(edges);
        }
        if let Some(new) = changed {
            if new != state.edges {
                state.edges = new;
                state.rebuild(&qh);
            }
        }
        queue.flush()?;
        // wait for events, but look at edge changes regularly
        if let Some(guard) = queue.prepare_read() {
            let fd = guard.connection_fd();
            let mut poll = libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(&fd),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd
            let ready = unsafe { libc::poll(&mut poll, 1, 250) };
            if ready > 0 {
                match guard.read() {
                    Ok(_) => {}
                    // readable, then nothing to read after all: normal,
                    // try again (was fatal, silently ending the strips)
                    Err(wayland_client::backend::WaylandError::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        queue.dispatch_pending(&mut state)?;
    }
}

impl State {
    /// One strip per edge in use, on the monitors forming that edge.
    fn rebuild(&mut self, qh: &QueueHandle<State>) {
        for strip in self.strips.drain(..) {
            strip.layer.destroy();
            strip.surface.destroy();
            if let Some(buffer) = strip.buffer {
                buffer.destroy();
            }
        }
        let outputs: Vec<_> = self.outputs.values().map(|(o, g)| (o.clone(), g)).collect();
        let (min_x, max_x, min_y, max_y) = outputs.iter().fold(
            (i32::MAX, i32::MIN, i32::MAX, i32::MIN),
            |(a, b, c, d), (_, g)| {
                (
                    a.min(g.x),
                    b.max(g.x + g.width),
                    c.min(g.y),
                    d.max(g.y + g.height),
                )
            },
        );
        let mut strips = vec![];
        for &edge in &self.edges {
            for (output, g) in &outputs {
                // only monitors at the outer edge, not between monitors
                let outer = match edge {
                    Position::Left => g.x == min_x,
                    Position::Right => g.x + g.width == max_x,
                    Position::Top => g.y == min_y,
                    Position::Bottom => g.y + g.height == max_y,
                };
                if !outer {
                    continue;
                }
                let surface = self.compositor.create_surface(qh, ());
                let layer = self.layer_shell.get_layer_surface(
                    &surface,
                    Some(output),
                    Layer::Overlay,
                    "lan-mouse-drag".into(),
                    qh,
                    (),
                );
                let (anchor, width, height) = match edge {
                    Position::Left => (Anchor::Left | Anchor::Top | Anchor::Bottom, 1, 0),
                    Position::Right => (Anchor::Right | Anchor::Top | Anchor::Bottom, 1, 0),
                    Position::Top => (Anchor::Top | Anchor::Left | Anchor::Right, 0, 1),
                    Position::Bottom => (Anchor::Bottom | Anchor::Left | Anchor::Right, 0, 1),
                };
                layer.set_anchor(anchor);
                layer.set_size(width, height);
                // over panels and bars too: the whole edge leads across
                layer.set_exclusive_zone(-1);
                layer.set_keyboard_interactivity(KeyboardInteractivity::None);
                surface.commit();
                strips.push(Strip {
                    surface,
                    layer,
                    buffer: None,
                });
            }
        }
        self.strips = strips;
    }

    fn is_strip(&self, surface: &WlSurface) -> bool {
        self.strips.iter().any(|s| &s.surface == surface)
    }

    /// A fully transparent buffer of `width` × `height`.
    fn transparent_buffer(
        &self,
        width: i32,
        height: i32,
        qh: &QueueHandle<State>,
    ) -> Option<WlBuffer> {
        let size = (width * height * 4) as usize;
        // SAFETY: a valid name; the returned descriptor is owned here
        let fd = unsafe { libc::memfd_create(c"lan-mouse-strip".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        // SAFETY: freshly created, not owned elsewhere
        let file = unsafe { File::from_raw_fd(fd) };
        // zeroed memory: transparent ARGB pixels
        file.set_len(size as u64).ok()?;

        let pool = self.shm.create_pool(file.as_fd(), size as i32, qh, ());
        let buffer = pool.create_buffer(
            0,
            width,
            height,
            width * 4,
            wl_shm::Format::Argb8888,
            qh,
            (),
        );
        pool.destroy();
        Some(buffer)
    }

    /// A drag entered a strip: forget the previous one.
    fn new_drag(&self, reading: bool) -> u64 {
        let Ok(mut seen) = SEEN.lock() else {
            return 0;
        };
        seen.generation += 1;
        seen.files = None;
        seen.reading = reading;
        seen.left = None;
        seen.generation
    }

    /// Read the dragged files from `offer` in the background.
    fn read_files(&self, offer: &WlDataOffer) {
        let generation = self.new_drag(true);
        let mut fds = [0; 2];
        // SAFETY: a valid array for the two descriptors
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return;
        }
        // SAFETY: freshly created, each owned exactly once
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        offer.receive(URI_LIST.into(), write.as_fd());
        let _ = self.connection.flush();
        // our copy of the write end must close, or reading never ends
        drop(write);
        std::thread::spawn(move || {
            let mut list = String::new();
            if File::from(read).read_to_string(&mut list).is_ok() {
                let files = parse_uri_list(&list);
                log::info!("files dragged to the edge: {}", files.len());
                if let Ok(mut seen) = SEEN.lock() {
                    // still the same drag (the read may outlast it)
                    if seen.generation == generation {
                        seen.files = Some(files);
                        seen.reading = false;
                    }
                }
            }
        });
    }

    fn forget_drag_soon(&mut self) {
        if let Ok(mut seen) = SEEN.lock() {
            seen.left.get_or_insert_with(Instant::now);
        }
    }
}

impl Dispatch<WlDataDevice, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlDataDevice,
        event: wl_data_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        log::trace!("drag strip: {event:?}");
        match event {
            wl_data_device::Event::DataOffer { id } => {
                state.offers.insert(id.id(), vec![]);
            }
            wl_data_device::Event::Enter {
                serial,
                surface,
                id: Some(offer),
                ..
            } if state.is_strip(&surface) => {
                let files = state
                    .offers
                    .get(&offer.id())
                    .is_some_and(|mimes| mimes.iter().any(|m| m == URI_LIST));
                log::info!("a drag reached the edge (files: {files})");
                if files {
                    offer.accept(serial, Some(URI_LIST.into()));
                    // a copy, never a move: dropping here must not take the
                    // files away from their source
                    if offer.version() >= 3 {
                        offer.set_actions(DndAction::Copy, DndAction::Copy);
                    }
                    state.read_files(&offer);
                    state.dragging = Some(offer);
                } else {
                    state.new_drag(false);
                    offer.accept(serial, None);
                }
            }
            wl_data_device::Event::Leave => {
                if let Some(offer) = state.dragging.take() {
                    state.offers.remove(&offer.id());
                    offer.destroy();
                    state.forget_drag_soon();
                }
            }
            wl_data_device::Event::Drop => {
                // dropped at the edge: finish it as a copy (nothing changes
                // for the source); the files are carried across already
                if let Some(offer) = state.dragging.take() {
                    if offer.version() >= 3 {
                        offer.finish();
                    }
                    state.offers.remove(&offer.id());
                    offer.destroy();
                    state.forget_drag_soon();
                }
            }
            // clipboard offers aren't ours to read
            wl_data_device::Event::Selection { id: Some(offer) } => {
                state.offers.remove(&offer.id());
                offer.destroy();
            }
            _ => {}
        }
    }

    wayland_client::event_created_child!(State, WlDataDevice, [
        wl_data_device::EVT_DATA_OFFER_OPCODE => (WlDataOffer, ()),
    ]);
}

impl Dispatch<WlDataOffer, ()> for State {
    fn event(
        state: &mut Self,
        offer: &WlDataOffer,
        event: wl_data_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_data_offer::Event::Offer { mime_type } = event {
            state.offers.entry(offer.id()).or_default().push(mime_type);
        }
    }
}

impl Dispatch<ZwlrLayerSurfaceV1, ()> for State {
    fn event(
        state: &mut Self,
        layer: &ZwlrLayerSurfaceV1,
        event: zwlr_layer_surface_v1::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_layer_surface_v1::Event::Configure {
                serial,
                width,
                height,
            } => {
                layer.ack_configure(serial);
                let (width, height) = (width.max(1) as i32, height.max(1) as i32);
                let buffer = state.transparent_buffer(width, height, qh);
                if let Some(strip) = state.strips.iter_mut().find(|s| &s.layer == layer) {
                    if let Some(buffer) = &buffer {
                        strip.surface.attach(Some(buffer), 0, 0);
                        strip.surface.damage_buffer(0, 0, width, height);
                    }
                    strip.surface.commit();
                    if let Some(old) = std::mem::replace(&mut strip.buffer, buffer) {
                        old.destroy();
                    }
                }
            }
            zwlr_layer_surface_v1::Event::Closed => {
                // its monitor went away: built again with the next change
                state.strips.retain(|s| &s.layer != layer);
            }
            _ => {}
        }
    }
}

impl Dispatch<WlSeat, ()> for State {
    fn event(
        state: &mut Self,
        seat: &WlSeat,
        event: wl_seat::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: wayland_client::WEnum::Value(capabilities),
        } = event
        {
            if capabilities.contains(wl_seat::Capability::Pointer) && state.cursor.is_none() {
                let pointer = seat.get_pointer(qh, ());
                state.cursor = state
                    .cursor_shapes
                    .as_ref()
                    .map(|shapes| shapes.get_pointer(&pointer, qh, ()));
            }
        }
    }
}

impl Dispatch<WlPointer, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlPointer,
        event: wl_pointer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // over a strip, the pointer looks as usual (instead of whatever the
        // last surface set, or nothing)
        if let wl_pointer::Event::Enter {
            serial, surface, ..
        } = event
        {
            if state.is_strip(&surface) {
                if let Some(cursor) = &state.cursor {
                    cursor.set_shape(serial, Shape::Default);
                }
            }
        }
    }
}

impl Dispatch<WlOutput, u32> for State {
    fn event(
        state: &mut Self,
        _: &WlOutput,
        event: wl_output::Event,
        name: &u32,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some((_, output)) = state.outputs.get_mut(name) else {
            return;
        };
        match event {
            wl_output::Event::Geometry { x, y, .. } => {
                output.x = x;
                output.y = y;
            }
            wl_output::Event::Mode {
                flags: wayland_client::WEnum::Value(flags),
                width,
                height,
                ..
            } if flags.contains(wl_output::Mode::Current) => {
                output.width = width;
                output.height = height;
            }
            wl_output::Event::Scale { factor } => output.scale = factor,
            wl_output::Event::Done => {
                // logical size, as the positions are
                let scale = output.scale.max(1);
                output.width /= scale;
                output.height /= scale;
                output.scale = 1;
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ignore WlCompositor);
delegate_noop!(State: ignore WlSurface);
delegate_noop!(State: ignore WlShm);
delegate_noop!(State: ignore WlShmPool);
delegate_noop!(State: ignore WlBuffer);
delegate_noop!(State: ignore ZwlrLayerShellV1);
delegate_noop!(State: ignore WlDataDeviceManager);
delegate_noop!(State: ignore WpCursorShapeManagerV1);
delegate_noop!(State: ignore WpCursorShapeDeviceV1);

#[cfg(test)]
mod tests {
    use super::*;

    /// Run by hand in a Wayland session: drag files to the left edge.
    #[test]
    #[ignore]
    fn watch_the_left_edge() {
        watch_edges(vec![Position::Left]);
        let mut last = None;
        for _ in 0..450 {
            let now = current_drag();
            if now != last {
                println!("drag at the edge: {now:?}");
                last = now;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    #[test]
    fn uri_lists_become_paths() {
        let list = "# a comment\r\nfile:///home/u/My%20Folder/a.txt\r\nfile://host/home/u/%C3%BC.txt\r\nhttps://example.com/x\r\n";
        assert_eq!(
            parse_uri_list(list),
            [
                PathBuf::from("/home/u/My Folder/a.txt"),
                PathBuf::from("/home/u/ü.txt")
            ]
        );
    }
}
