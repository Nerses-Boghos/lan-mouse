//! The local monitors and the desktop they span, used to line up screens
//! between devices.

/// Bounding box of all monitors, in logical pixels (the coordinates the
/// pointer moves in).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl DesktopBounds {
    fn union(self, other: Self) -> Self {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.width as i32).max(other.x + other.width as i32);
        let bottom = (self.y + self.height as i32).max(other.y + other.height as i32);
        Self {
            x,
            y,
            width: (right - x) as u32,
            height: (bottom - y) as u32,
        }
    }

    pub fn enclosing(monitors: impl IntoIterator<Item = Self>) -> Option<Self> {
        monitors
            .into_iter()
            .filter(|m| m.width > 0 && m.height > 0)
            .reduce(Self::union)
    }
}

/// The current desktop bounds, if the platform can report them.
pub fn desktop_bounds() -> Option<DesktopBounds> {
    DesktopBounds::enclosing(displays()?)
}

/// Every monitor's area, if the platform can report them.
pub fn displays() -> Option<Vec<DesktopBounds>> {
    let displays: Vec<_> = platform::displays()?
        .into_iter()
        .filter(|m| m.width > 0 && m.height > 0)
        .collect();
    (!displays.is_empty()).then_some(displays)
}

#[cfg(target_os = "macos")]
mod platform {
    use super::DesktopBounds;
    use core_graphics::display::CGDisplay;

    pub(super) fn displays() -> Option<Vec<DesktopBounds>> {
        let displays = CGDisplay::active_displays().ok()?;
        Some(
            displays
                .into_iter()
                .map(|id| {
                    let b = CGDisplay::new(id).bounds();
                    DesktopBounds {
                        x: b.origin.x as i32,
                        y: b.origin.y as i32,
                        width: b.size.width as u32,
                        height: b.size.height as u32,
                    }
                })
                .collect(),
        )
    }
}

#[cfg(layer_shell)]
mod platform {
    //! Wayland: the logical geometry of every output, from xdg-output.

    use super::DesktopBounds;
    use std::collections::HashMap;
    use wayland_client::{
        Connection, Dispatch, QueueHandle, delegate_noop,
        globals::{GlobalListContents, registry_queue_init},
        protocol::{wl_output::WlOutput, wl_registry},
    };
    use wayland_protocols::xdg::xdg_output::zv1::client::{
        zxdg_output_manager_v1::ZxdgOutputManagerV1,
        zxdg_output_v1::{self, ZxdgOutputV1},
    };

    /// An output's logical geometry, filled in as xdg-output reports it.
    #[derive(Default)]
    struct Geometry {
        position: Option<(i32, i32)>,
        size: Option<(i32, i32)>,
    }

    #[derive(Default)]
    struct State {
        outputs: HashMap<u32, Geometry>,
    }

    pub(super) fn displays() -> Option<Vec<DesktopBounds>> {
        let conn = Connection::connect_to_env().ok()?;
        let (globals, mut queue) = registry_queue_init::<State>(&conn).ok()?;
        let qh = queue.handle();
        let manager: ZxdgOutputManagerV1 = globals.bind(&qh, 1..=3, ()).ok()?;
        let outputs: Vec<(u32, WlOutput)> = globals.contents().with_list(|list| {
            list.iter()
                .filter(|g| g.interface == "wl_output")
                .map(|g| {
                    (
                        g.name,
                        globals.registry().bind(g.name, g.version.min(4), &qh, ()),
                    )
                })
                .collect()
        });
        for (name, output) in &outputs {
            manager.get_xdg_output(output, &qh, *name);
        }
        let mut state = State::default();
        queue.roundtrip(&mut state).ok()?;
        Some(
            state
                .outputs
                .values()
                .filter_map(|output| {
                    let ((x, y), (w, h)) = (output.position?, output.size?);
                    Some(DesktopBounds {
                        x,
                        y,
                        width: w.max(0) as u32,
                        height: h.max(0) as u32,
                    })
                })
                .collect(),
        )
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

    impl Dispatch<ZxdgOutputV1, u32> for State {
        fn event(
            state: &mut Self,
            _: &ZxdgOutputV1,
            event: zxdg_output_v1::Event,
            name: &u32,
            _: &Connection,
            _: &QueueHandle<Self>,
        ) {
            let output = state.outputs.entry(*name).or_default();
            match event {
                zxdg_output_v1::Event::LogicalPosition { x, y } => output.position = Some((x, y)),
                zxdg_output_v1::Event::LogicalSize { width, height } => {
                    output.size = Some((width, height))
                }
                _ => {}
            }
        }
    }

    delegate_noop!(State: ignore WlOutput);
    delegate_noop!(State: ignore ZxdgOutputManagerV1);
}

#[cfg(not(any(target_os = "macos", layer_shell)))]
mod platform {
    use super::DesktopBounds;

    pub(super) fn displays() -> Option<Vec<DesktopBounds>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_enclose_all_monitors() {
        let laptop = DesktopBounds {
            x: 0,
            y: 0,
            width: 1366,
            height: 768,
        };
        let above = DesktopBounds {
            x: -200,
            y: -1080,
            width: 1920,
            height: 1080,
        };
        assert_eq!(
            DesktopBounds::enclosing([laptop, above]),
            Some(DesktopBounds {
                x: -200,
                y: -1080,
                width: 1920,
                height: 1848
            })
        );
        assert_eq!(DesktopBounds::enclosing([]), None);
    }
}

#[cfg(test)]
mod live {
    /// Prints the real desktop: `cargo test -p input-capture -- --ignored --nocapture`
    #[test]
    #[ignore = "needs a graphical session"]
    fn print_desktop_bounds() {
        println!("desktop bounds: {:?}", super::desktop_bounds());
    }
}
