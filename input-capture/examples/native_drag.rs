//! Experiment: start a real Wayland drag of files without a window of our
//! own, the way Lan Mouse would when a drag from another device arrives.
//! A transparent overlay covers the screen; the next button press on it
//! (sent by the other device's mouse, through Lan Mouse's virtual pointer)
//! starts the drag with a small icon under the cursor, and the overlay
//! stops taking input so the drag can reach the windows below.
//!
//!     native_drag FILE...

use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, FromRawFd},
};

use wayland_client::{
    Connection, Dispatch, QueueHandle, WEnum, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{
        wl_buffer::WlBuffer,
        wl_compositor::WlCompositor,
        wl_data_device::WlDataDevice,
        wl_data_device_manager::{DndAction, WlDataDeviceManager},
        wl_data_offer::WlDataOffer,
        wl_data_source::{self, WlDataSource},
        wl_pointer::{self, WlPointer},
        wl_region::WlRegion,
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

struct State {
    compositor: WlCompositor,
    shm: WlShm,
    manager: WlDataDeviceManager,
    device: WlDataDevice,
    overlay: WlSurface,
    pointer: Option<WlPointer>,
    uris: String,
    dragging: bool,
    done: bool,
}

fn main() {
    let uris: String = std::env::args()
        .skip(1)
        .map(|path| format!("file://{path}\r\n"))
        .collect();
    let conn = Connection::connect_to_env().expect("wayland");
    let (globals, mut queue) = registry_queue_init::<State>(&conn).expect("registry");
    let qh = queue.handle();
    let compositor: WlCompositor = globals.bind(&qh, 4..=6, ()).expect("compositor");
    let shm: WlShm = globals.bind(&qh, 1..=1, ()).expect("shm");
    let seat: WlSeat = globals.bind(&qh, 1..=7, ()).expect("seat");
    let manager: WlDataDeviceManager = globals.bind(&qh, 3..=3, ()).expect("ddm");
    let layer_shell: ZwlrLayerShellV1 = globals.bind(&qh, 1..=4, ()).expect("layer shell");
    let device = manager.get_data_device(&seat, &qh, ());

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
        compositor,
        shm,
        manager,
        device,
        overlay,
        pointer: None,
        uris,
        dragging: false,
        done: false,
    };
    println!("ready");
    while !state.done {
        queue.blocking_dispatch(&mut state).expect("dispatch");
    }
}

impl State {
    /// A buffer of `w`x`h` filled with `argb` (premultiplied).
    fn buffer(&self, w: i32, h: i32, argb: u32, qh: &QueueHandle<Self>) -> WlBuffer {
        let size = (w * h * 4) as usize;
        let fd = unsafe { libc::memfd_create(c"lm-drop".as_ptr(), libc::MFD_CLOEXEC) };
        let mut file = unsafe { File::from_raw_fd(fd) };
        let pixels: Vec<u8> = std::iter::repeat_n(argb.to_le_bytes(), (w * h) as usize)
            .flatten()
            .collect();
        file.write_all(&pixels).expect("pixels");
        let pool = self.shm.create_pool(file.as_fd(), size as i32, qh, ());
        pool.create_buffer(0, w, h, w * 4, wl_shm::Format::Argb8888, qh, ())
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
        if let zwlr_layer_surface_v1::Event::Configure {
            serial,
            width,
            height,
        } = event
        {
            layer.ack_configure(serial);
            // transparent, but there: it takes the next button press
            let buffer = state.buffer(width.max(1) as i32, height.max(1) as i32, 0, qh);
            state.overlay.attach(Some(&buffer), 0, 0);
            state.overlay.commit();
            println!("overlay {width}x{height}");
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
            wl_pointer::Event::Enter { .. } => println!("pointer on the overlay"),
            wl_pointer::Event::Button {
                serial,
                state: WEnum::Value(wl_pointer::ButtonState::Pressed),
                ..
            } if !state.dragging => {
                state.dragging = true;
                let source = state.manager.create_data_source(qh, ());
                source.offer("text/uri-list".into());
                source.set_actions(DndAction::Copy);
                // the ghost: a small square under the cursor
                let icon = state.compositor.create_surface(qh, ());
                let buffer = state.buffer(32, 32, 0xc0_4a_6c_d0, qh);
                icon.attach(Some(&buffer), 0, 0);
                icon.commit();
                let icon = std::env::var_os("NATIVE_DRAG_NOICON")
                    .is_none()
                    .then_some(icon);
                state
                    .device
                    .start_drag(Some(&source), &state.overlay, icon.as_ref(), serial);
                // let the drag reach what's below: the overlay goes away
                // (unmapped, not destroyed: the drag started from it)
                if std::env::var_os("NATIVE_DRAG_KEEP").is_some() {
                    // stays the drop target: a check that the drag works at all
                } else if std::env::var_os("NATIVE_DRAG_REGION").is_some() {
                    let nothing = state.compositor.create_region(qh, ());
                    state.overlay.set_input_region(Some(&nothing));
                } else {
                    state.overlay.attach(None, 0, 0);
                }
                state.overlay.commit();
                println!("{:?} drag started", std::time::SystemTime::now());
            }
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
            wl_data_source::Event::Send { fd, .. } => {
                let mut file = File::from(fd);
                let _ = file.write_all(state.uris.as_bytes());
                println!("sent the files");
            }
            wl_data_source::Event::Action { dnd_action } => println!("drag action: {dnd_action:?}"),
            wl_data_source::Event::Target { mime_type } => {
                println!("target accepts: {mime_type:?}")
            }
            wl_data_source::Event::DndDropPerformed => println!("dropped"),
            wl_data_source::Event::DndFinished => {
                println!("drag finished");
                state.done = true;
            }
            wl_data_source::Event::Cancelled => {
                println!("{:?} drag cancelled", std::time::SystemTime::now());
                state.done = true;
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
        event: wayland_client::protocol::wl_data_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        use wayland_client::protocol::wl_data_device::Event;
        match event {
            Event::Enter { .. } => println!("our own drag entered the overlay"),
            Event::Leave => println!("our own drag left the overlay"),
            _ => {}
        }
    }

    // our own drag passes over the overlay too: its offers are ignored
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
delegate_noop!(State: ignore WlRegion);
delegate_noop!(State: ignore WlDataOffer);
delegate_noop!(State: ignore WlDataDeviceManager);
delegate_noop!(State: ignore ZwlrLayerShellV1);
