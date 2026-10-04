//! Test helper: a virtual pointer driven by commands on stdin, one per line,
//! like another device's mouse moving this one through Lan Mouse. For
//! end-to-end tests in a headless compositor.
//!
//!     move DX DY      relative motion
//!     to X Y          absolute position (on a WIDTHxHEIGHT space, see below)
//!     press | release left button
//!     sleep MS
//!
//!     virtual_pointer WIDTH HEIGHT

use std::{
    io::BufRead,
    time::{Duration, Instant},
};

use wayland_client::{
    Connection, Dispatch, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{wl_pointer, wl_registry, wl_seat::WlSeat},
};
use wayland_protocols_wlr::virtual_pointer::v1::client::{
    zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1,
    zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1,
};

struct State;

const BTN_LEFT: u32 = 0x110;

fn main() {
    let mut args = std::env::args().skip(1);
    let width: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(1366);
    let height: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(768);
    let conn = Connection::connect_to_env().expect("wayland");
    let (globals, mut queue) = registry_queue_init::<State>(&conn).expect("registry");
    let qh = queue.handle();
    let seat: WlSeat = globals.bind(&qh, 1..=7, ()).expect("seat");
    let manager: ZwlrVirtualPointerManagerV1 = globals
        .bind(&qh, 1..=2, ())
        .expect("virtual pointer manager");
    let pointer = manager.create_virtual_pointer(Some(&seat), &qh, ());
    let start = Instant::now();
    let now = || start.elapsed().as_millis() as u32;
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["move", dx, dy] => {
                pointer.motion(now(), dx.parse().unwrap(), dy.parse().unwrap());
                pointer.frame();
            }
            ["to", x, y] => {
                pointer.motion_absolute(
                    now(),
                    x.parse().unwrap(),
                    y.parse().unwrap(),
                    width,
                    height,
                );
                pointer.frame();
            }
            ["press"] | ["release"] => {
                let state = if words[0] == "press" {
                    wl_pointer::ButtonState::Pressed
                } else {
                    wl_pointer::ButtonState::Released
                };
                pointer.button(now(), BTN_LEFT, state);
                pointer.frame();
            }
            ["sleep", ms] => std::thread::sleep(Duration::from_millis(ms.parse().unwrap())),
            [] => {}
            _ => eprintln!("unknown command: {line}"),
        }
        queue.roundtrip(&mut State).expect("roundtrip");
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

delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore ZwlrVirtualPointerManagerV1);
delegate_noop!(State: ignore ZwlrVirtualPointerV1);
