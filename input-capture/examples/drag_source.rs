//! Test helper: a window covering the screen that starts dragging files when
//! clicked, like a file manager. For end-to-end tests in a headless
//! compositor (see omarchy-lan-mouse/dev/e2e-drag-sway.sh).
//!
//!     drag_source FILE...

use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, FromRawFd},
};

use wayland_client::{
    Connection, Dispatch, QueueHandle, delegate_noop,
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
        wl_seat::WlSeat,
        wl_shm::{self, WlShm},
        wl_shm_pool::WlShmPool,
        wl_surface::WlSurface,
    },
};
use wayland_protocols::xdg::shell::client::{
    xdg_surface::{self, XdgSurface},
    xdg_toplevel::{self, XdgToplevel},
    xdg_wm_base::{self, XdgWmBase},
};

struct State {
    shm: WlShm,
    manager: WlDataDeviceManager,
    device: WlDataDevice,
    surface: WlSurface,
    uris: String,
    configured: bool,
    /// as configured; the whole screen when fullscreen
    size: (i32, i32),
    /// once the seat has a pointer (headless: when a virtual one appears)
    pointer: Option<WlPointer>,
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
    // kept by the surface
    let shm: WlShm = globals.bind(&qh, 1..=1, ()).expect("shm");
    let wm: XdgWmBase = globals.bind(&qh, 1..=5, ()).expect("xdg_wm_base");
    let seat: WlSeat = globals.bind(&qh, 1..=7, ()).expect("seat");
    let manager: WlDataDeviceManager = globals.bind(&qh, 3..=3, ()).expect("ddm");
    let device = manager.get_data_device(&seat, &qh, ());
    let surface = compositor.create_surface(&qh, ());
    let xdg = wm.get_xdg_surface(&surface, &qh, ());
    let toplevel = xdg.get_toplevel(&qh, ());
    toplevel.set_title("drag source".into());
    if std::env::var_os("DRAG_SOURCE_WINDOWED").is_none() {
        toplevel.set_fullscreen(None);
    }
    surface.commit();
    let mut state = State {
        pointer: None,
        shm,
        manager,
        device,
        surface,
        uris,
        configured: false,
        size: (1366, 768),
    };
    println!("ready");
    loop {
        queue.blocking_dispatch(&mut state).expect("dispatch");
    }
}

impl State {
    fn draw(&self, width: i32, height: i32, qh: &QueueHandle<Self>) {
        let size = (width * height * 4) as usize;
        let fd = unsafe { libc::memfd_create(c"drag-source".as_ptr(), libc::MFD_CLOEXEC) };
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(size as u64).expect("size");
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
        self.surface.attach(Some(&buffer), 0, 0);
        self.surface.damage_buffer(0, 0, width, height);
        self.surface.commit();
    }
}

impl Dispatch<XdgSurface, ()> for State {
    fn event(
        state: &mut Self,
        xdg: &XdgSurface,
        event: xdg_surface::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let xdg_surface::Event::Configure { serial } = event {
            // acknowledge first, then draw (the other way round is an error)
            xdg.ack_configure(serial);
            if !state.configured {
                state.configured = true;
                let (width, height) = state.size;
                state.draw(width, height, qh);
            }
        }
    }
}

impl Dispatch<XdgToplevel, ()> for State {
    fn event(
        state: &mut Self,
        _: &XdgToplevel,
        event: xdg_toplevel::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_toplevel::Event::Configure { width, height, .. } = event {
            if width > 0 && height > 0 {
                state.size = (width, height);
            }
        }
    }
}

impl Dispatch<XdgWmBase, ()> for State {
    fn event(
        _: &mut Self,
        wm: &XdgWmBase,
        event: xdg_wm_base::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            wm.pong(serial);
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
        // a press starts the drag, like grabbing a file
        if let wl_pointer::Event::Button {
            serial,
            state: wayland_client::WEnum::Value(wl_pointer::ButtonState::Pressed),
            ..
        } = event
        {
            let source = state.manager.create_data_source(qh, ());
            source.offer("text/uri-list".into());
            source.set_actions(DndAction::Copy | DndAction::Move);
            state
                .device
                .start_drag(Some(&source), &state.surface, None, serial);
            println!("{:?} drag started", std::time::SystemTime::now());
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
            }
            wl_data_source::Event::DndFinished => println!("drag finished"),
            wl_data_source::Event::Cancelled => {
                println!("{:?} drag cancelled", std::time::SystemTime::now())
            }
            wl_data_source::Event::Action { dnd_action } => println!("drag action: {dnd_action:?}"),
            wl_data_source::Event::DndDropPerformed => println!("drag dropped"),
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
impl Dispatch<WlSeat, ()> for State {
    fn event(
        state: &mut Self,
        seat: &WlSeat,
        event: wayland_client::protocol::wl_seat::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        use wayland_client::protocol::wl_seat::{Capability, Event};
        if let Event::Capabilities {
            capabilities: wayland_client::WEnum::Value(caps),
        } = event
        {
            if caps.contains(Capability::Pointer) && state.pointer.is_none() {
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

    // the drag passes over this window too: offers to it are ignored
    wayland_client::event_created_child!(State, WlDataDevice, [
        wayland_client::protocol::wl_data_device::EVT_DATA_OFFER_OPCODE => (WlDataOffer, ()),
    ]);
}

delegate_noop!(State: ignore WlDataOffer);
delegate_noop!(State: ignore WlDataDeviceManager);
