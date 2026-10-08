//! Test helper: an ordinary window that accepts dropped files and prints
//! what reaches it, to tell compositor behavior from Lan Mouse's own.

use std::{
    fs::File,
    io::Read,
    os::fd::{AsFd, FromRawFd, OwnedFd},
};

use wayland_client::{
    Connection, Dispatch, Proxy, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{
        wl_buffer::WlBuffer,
        wl_compositor::WlCompositor,
        wl_data_device::{self, WlDataDevice},
        wl_data_device_manager::{DndAction, WlDataDeviceManager},
        wl_data_offer::{self, WlDataOffer},
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
    surface: WlSurface,
    size: (i32, i32),
    drawn: bool,
    offer: Option<WlDataOffer>,
    conn: Connection,
}

fn main() {
    let conn = Connection::connect_to_env().expect("wayland");
    let (globals, mut queue) = registry_queue_init::<State>(&conn).expect("registry");
    let qh = queue.handle();
    let compositor: WlCompositor = globals.bind(&qh, 4..=6, ()).expect("compositor");
    let shm: WlShm = globals.bind(&qh, 1..=1, ()).expect("shm");
    let wm: XdgWmBase = globals.bind(&qh, 1..=5, ()).expect("wm");
    let seat: WlSeat = globals.bind(&qh, 1..=7, ()).expect("seat");
    let manager: WlDataDeviceManager = globals.bind(&qh, 3..=3, ()).expect("ddm");
    manager.get_data_device(&seat, &qh, ());
    let surface = compositor.create_surface(&qh, ());
    let xdg = wm.get_xdg_surface(&surface, &qh, ());
    xdg.get_toplevel(&qh, ()).set_title("drop target".into());
    surface.commit();
    let mut state = State {
        shm,
        surface,
        size: (600, 768),
        drawn: false,
        offer: None,
        conn: conn.clone(),
    };
    println!("ready");
    loop {
        queue.blocking_dispatch(&mut state).expect("dispatch");
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
        match event {
            wl_data_device::Event::Enter {
                serial,
                id: Some(offer),
                ..
            } => {
                println!("drag entered");
                offer.accept(serial, Some("text/uri-list".into()));
                offer.set_actions(DndAction::Copy, DndAction::Copy);
                state.offer = Some(offer);
            }
            wl_data_device::Event::Enter { id: None, .. } => {
                println!("drag entered without an offer")
            }
            wl_data_device::Event::Leave => println!("drag left"),
            wl_data_device::Event::Motion { .. } => {}
            wl_data_device::Event::Drop => {
                println!("dropped");
                if let Some(offer) = state.offer.take() {
                    let mut fds = [0; 2];
                    unsafe { libc::pipe(fds.as_mut_ptr()) };
                    let (read, write) =
                        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
                    offer.receive("text/uri-list".into(), write.as_fd());
                    let _ = state.conn.flush();
                    drop(write);
                    let mut list = String::new();
                    let _ = File::from(read).read_to_string(&mut list);
                    println!("received: {}", list.trim());
                    offer.finish();
                    offer.destroy();
                }
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
        _: &mut Self,
        offer: &WlDataOffer,
        event: wl_data_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let wl_data_offer::Event::Offer { mime_type } = event {
            let _ = (offer.id(), mime_type);
        }
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
            xdg.ack_configure(serial);
            if !state.drawn {
                state.drawn = true;
                let (w, h) = state.size;
                let size = (w * h * 4) as usize;
                let fd = unsafe { libc::memfd_create(c"drop-target".as_ptr(), libc::MFD_CLOEXEC) };
                let file = unsafe { File::from_raw_fd(fd) };
                file.set_len(size as u64).unwrap();
                let pool = state.shm.create_pool(file.as_fd(), size as i32, qh, ());
                let buffer = pool.create_buffer(0, w, h, w * 4, wl_shm::Format::Argb8888, qh, ());
                state.surface.attach(Some(&buffer), 0, 0);
                state.surface.damage_buffer(0, 0, w, h);
                state.surface.commit();
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
delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore WlDataDeviceManager);
