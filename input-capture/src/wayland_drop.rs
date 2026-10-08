//! A real drag on this desktop for files dragged over from another device,
//! so they can be dropped on any window, with an image under the cursor.
//!
//! Wayland only lets a client start a drag from a button press on its own
//! surface. So a transparent overlay covers the screen; once the pointer
//! is on it, Lan Mouse presses the button through its virtual pointer
//! (see [`NativeDrop::ready`]), the press starts the drag, and the overlay
//! goes away so the drag reaches the windows below. The other device's
//! mouse then moves the drag, and letting go drops it. The files may still
//! be arriving: a window asking for them waits until they are there.

use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, AsRawFd, FromRawFd},
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

use wayland_client::{
    Connection, Dispatch, EventQueue, QueueHandle, WEnum, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{
        wl_buffer::WlBuffer,
        wl_compositor::WlCompositor,
        wl_data_device::WlDataDevice,
        wl_data_device_manager::{DndAction, WlDataDeviceManager},
        wl_data_offer::WlDataOffer,
        wl_data_source::{self, WlDataSource},
        wl_pointer::{self, WlPointer},
        wl_registry,
        wl_seat::{self, WlSeat},
        wl_shm::{self, WlShm},
        wl_shm_pool::WlShmPool,
        wl_surface::WlSurface,
    },
};
use wayland_protocols_wlr::layer_shell::v1::client::{
    zwlr_layer_shell_v1::{Layer, ZwlrLayerShellV1},
    zwlr_layer_surface_v1::{self, Anchor, KeyboardInteractivity, ZwlrLayerSurfaceV1},
};

/// How long a window asking for the files waits for them to arrive.
const FILES_WAIT: Duration = Duration::from_secs(120);

#[derive(Default)]
struct Shared {
    /// the pointer is on the overlay: the button can be pressed
    ready: bool,
    /// the drag ended, dropped or not
    finished: bool,
    /// asked to stop
    cancelled: bool,
    files: Option<Vec<PathBuf>>,
}

/// A drag being set up or under way, see the module docs.
#[derive(Clone)]
pub struct NativeDrop {
    shared: Arc<(Mutex<Shared>, Condvar)>,
}

impl NativeDrop {
    /// Put the overlay up. `None` when there is no compositor to do it with.
    pub fn start() -> Option<Self> {
        let shared = Arc::new((Mutex::new(Shared::default()), Condvar::new()));
        let drop = Self { shared };
        let thread_drop = drop.clone();
        std::thread::Builder::new()
            .name("native-drop".into())
            .spawn(move || {
                if let Err(e) = run(&thread_drop) {
                    log::warn!("could not start a drag here: {e}");
                }
                thread_drop.update(|s| s.finished = true);
            })
            .ok()?;
        Some(drop)
    }

    /// The pointer is on the overlay: press the button now to start the drag.
    pub fn ready(&self) -> bool {
        self.with(|s| s.ready && !s.finished)
    }

    /// The drag is over (dropped, given up, or it never started).
    pub fn finished(&self) -> bool {
        self.with(|s| s.finished)
    }

    /// The files arrived, at these paths: a window they were dropped on gets
    /// them.
    pub fn deliver(&self, files: Vec<PathBuf>) {
        self.update(|s| s.files = Some(files));
    }

    /// End the drag without dropping (the other device took it back).
    pub fn cancel(&self) {
        self.update(|s| s.cancelled = true);
    }

    fn with<T>(&self, f: impl FnOnce(&Shared) -> T) -> T {
        f(&self.shared.0.lock().expect("lock"))
    }

    fn update(&self, f: impl FnOnce(&mut Shared)) {
        f(&mut self.shared.0.lock().expect("lock"));
        self.shared.1.notify_all();
    }

    /// The files, once they arrived (`None`: never, or cancelled).
    fn wait_for_files(&self) -> Option<Vec<PathBuf>> {
        let (lock, cond) = &*self.shared;
        let deadline = Instant::now() + FILES_WAIT;
        let mut shared = lock.lock().expect("lock");
        loop {
            if shared.cancelled {
                return None;
            }
            if let Some(files) = &shared.files {
                return Some(files.clone());
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            shared = cond.wait_timeout(shared, left).expect("lock").0;
        }
    }
}

struct State {
    drop: NativeDrop,
    compositor: WlCompositor,
    shm: WlShm,
    manager: WlDataDeviceManager,
    device: WlDataDevice,
    overlay: WlSurface,
    layer: ZwlrLayerSurfaceV1,
    pointer: Option<WlPointer>,
    source: Option<WlDataSource>,
    /// the drag ended: stop
    done: bool,
}

fn run(drop: &NativeDrop) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::connect_to_env()?;
    let (globals, mut queue): (_, EventQueue<State>) = registry_queue_init(&connection)?;
    let qh = queue.handle();
    let compositor: WlCompositor = globals.bind(&qh, 4..=6, ())?;
    let shm: WlShm = globals.bind(&qh, 1..=1, ())?;
    let seat: WlSeat = globals.bind(&qh, 1..=7, ())?;
    let manager: WlDataDeviceManager = globals.bind(&qh, 3..=3, ())?;
    let layer_shell: ZwlrLayerShellV1 = globals.bind(&qh, 1..=4, ())?;
    let device = manager.get_data_device(&seat, &qh, ());

    // on the output under the pointer (the compositor's choice)
    let overlay = compositor.create_surface(&qh, ());
    let layer = layer_shell.get_layer_surface(
        &overlay,
        None,
        Layer::Overlay,
        "lan-mouse-drop".into(),
        &qh,
        (),
    );
    layer.set_anchor(Anchor::Top | Anchor::Bottom | Anchor::Left | Anchor::Right);
    layer.set_exclusive_zone(-1);
    layer.set_keyboard_interactivity(KeyboardInteractivity::None);
    overlay.commit();

    let mut state = State {
        drop: drop.clone(),
        compositor,
        shm,
        manager,
        device,
        overlay,
        layer,
        pointer: None,
        source: None,
        done: false,
    };
    // never stays up for nothing: the press comes right away, or not at all
    let give_up = Instant::now() + Duration::from_secs(3);
    loop {
        connection.flush()?;
        if let Some(guard) = queue.prepare_read() {
            let mut poll = libc::pollfd {
                fd: guard.connection_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd
            if unsafe { libc::poll(&mut poll, 1, 50) } > 0 {
                match guard.read() {
                    Ok(_) => {}
                    Err(wayland_client::backend::WaylandError::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        queue.dispatch_pending(&mut state)?;
        if state.done {
            break;
        }
        if drop.with(|s| s.cancelled) {
            log::info!("the drag was taken back");
            break;
        }
        if state.source.is_none() && Instant::now() > give_up {
            log::info!("the drag here didn't start in time");
            break;
        }
    }
    // destroying the source ends a drag still under way, without a drop
    if let Some(source) = state.source.take() {
        source.destroy();
    }
    state.layer.destroy();
    state.overlay.destroy();
    connection.flush()?;
    Ok(())
}

impl State {
    /// A buffer of `w`x`h` with these pixels (ARGB, premultiplied).
    fn buffer(&self, w: i32, h: i32, pixels: &[u32], qh: &QueueHandle<Self>) -> Option<WlBuffer> {
        let size = (w * h * 4) as usize;
        // SAFETY: a fresh anonymous file, owned below
        let fd = unsafe { libc::memfd_create(c"lan-mouse-drop".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        // SAFETY: fd was just created and is owned by nothing else
        let mut file = unsafe { File::from_raw_fd(fd) };
        let bytes: Vec<u8> = pixels.iter().flat_map(|p| p.to_le_bytes()).collect();
        file.write_all(&bytes).ok()?;
        let pool = self.shm.create_pool(file.as_fd(), size as i32, qh, ());
        let buffer = pool.create_buffer(0, w, h, w * 4, wl_shm::Format::Argb8888, qh, ());
        pool.destroy();
        Some(buffer)
    }

    fn start_drag(&mut self, serial: u32, qh: &QueueHandle<Self>) {
        let source = self.manager.create_data_source(qh, ());
        source.offer("text/uri-list".into());
        source.set_actions(DndAction::Copy);
        let icon = self.compositor.create_surface(qh, ());
        let (w, h, pixels) = ghost();
        if let Some(buffer) = self.buffer(w, h, &pixels, qh) {
            icon.attach(Some(&buffer), 0, 0);
            icon.commit();
        }
        self.device
            .start_drag(Some(&source), &self.overlay, Some(&icon), serial);
        self.source = Some(source);
        // out of the way (unmapped, not destroyed: the drag started on it),
        // so the drag reaches the windows below
        self.overlay.attach(None, 0, 0);
        self.overlay.commit();
        log::info!("the drag continues here");
    }
}

/// The image under the cursor: a page with a folded corner.
fn ghost() -> (i32, i32, Vec<u32>) {
    const W: i32 = 28;
    const H: i32 = 34;
    const FOLD: i32 = 9;
    let paper = 0xe6_f4_f5_fa; // ARGB, premultiplied: light, slightly see-through
    let edge = 0xf0_5a_60_78;
    let mut pixels = vec![0u32; (W * H) as usize];
    for y in 0..H {
        for x in 0..W {
            // the folded corner is cut off the top right
            let cut = x > W - 1 - FOLD + y;
            if cut && y < FOLD {
                continue;
            }
            let border = x == 0
                || y == H - 1
                || x == W - 1
                || y == 0
                || (x - (W - 1 - FOLD) == y && y <= FOLD);
            pixels[(y * W + x) as usize] = if border { edge } else { paper };
        }
    }
    (W, H, pixels)
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
                if state.source.is_some() {
                    return;
                }
                // transparent, but there: it takes the press
                let (w, h) = (width.max(1) as i32, height.max(1) as i32);
                let pixels = vec![0u32; (w * h) as usize];
                if let Some(buffer) = state.buffer(w, h, &pixels, qh) {
                    state.overlay.attach(Some(&buffer), 0, 0);
                    state.overlay.commit();
                }
            }
            zwlr_layer_surface_v1::Event::Closed => state.done = true,
            _ => {}
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
        qh: &QueueHandle<Self>,
    ) {
        match event {
            wl_pointer::Event::Enter { .. } if state.source.is_none() => {
                state.drop.update(|s| s.ready = true);
            }
            wl_pointer::Event::Button {
                serial,
                state: WEnum::Value(wl_pointer::ButtonState::Pressed),
                ..
            } if state.source.is_none() => state.start_drag(serial, qh),
            _ => {}
        }
    }
}

impl Dispatch<WlDataSource, ()> for State {
    fn event(
        state: &mut Self,
        _: &WlDataSource,
        event: wl_data_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            // a window wants the files: once they're here (on a thread of
            // its own, so the drag keeps going meanwhile)
            wl_data_source::Event::Send { fd, .. } => {
                let drop = state.drop.clone();
                std::thread::spawn(move || {
                    let mut file = File::from(fd);
                    if let Some(files) = drop.wait_for_files() {
                        let list: String = files
                            .iter()
                            .map(|p| format!("file://{}\r\n", encode(&p.to_string_lossy())))
                            .collect();
                        let _ = file.write_all(list.as_bytes());
                    }
                });
            }
            wl_data_source::Event::DndDropPerformed => log::info!("dropped here"),
            wl_data_source::Event::DndFinished | wl_data_source::Event::Cancelled => {
                state.done = true;
            }
            _ => {}
        }
    }
}

/// `path` for a `file://` URI.
fn encode(path: &str) -> String {
    path.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
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
            capabilities: WEnum::Value(caps),
        } = event
        {
            if caps.contains(wl_seat::Capability::Pointer) && state.pointer.is_none() {
                state.pointer = Some(seat.get_pointer(qh, ()));
            }
        }
    }
}

impl Dispatch<WlDataDevice, ()> for State {
    fn event(
        _: &mut Self,
        _: &WlDataDevice,
        _: wayland_client::protocol::wl_data_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }

    // the drag passes over the overlay too: offers to it are ignored
    wayland_client::event_created_child!(State, WlDataDevice, [
        wayland_client::protocol::wl_data_device::EVT_DATA_OFFER_OPCODE => (WlDataOffer, ()),
    ]);
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
delegate_noop!(State: ignore WlDataOffer);
delegate_noop!(State: ignore WlDataDeviceManager);
delegate_noop!(State: ignore ZwlrLayerShellV1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ghost_is_a_page_with_a_folded_corner() {
        let (w, h, pixels) = ghost();
        assert_eq!(pixels.len(), (w * h) as usize);
        // the corner is cut, the rest is drawn
        assert_eq!(pixels[(w - 1) as usize], 0);
        assert_ne!(pixels[(h / 2 * w + w / 2) as usize], 0);
    }

    #[test]
    fn paths_become_uris() {
        assert_eq!(encode("/a b/ü.txt"), "/a%20b/%C3%BC.txt");
    }
}
