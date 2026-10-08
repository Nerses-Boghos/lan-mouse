//! What the menu bar item says and does: one line on what's going on, and
//! pausing sharing (see [`crate::macos_status_item`]).

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use adw::prelude::*;
use lan_mouse_ipc::{ClientHandle, FrontendEvent, FrontendRequest};

use crate::window::Window;

#[cfg(target_os = "macos")]
use crate::macos_status_item;

/// Elsewhere there is no menu bar item: this keeps the logic checked.
#[cfg(not(target_os = "macos"))]
mod macos_status_item {
    pub fn on_pause(_: impl Fn() + 'static) {}
    pub fn set_status(_: &str, _: bool) {}
}

#[derive(Default)]
struct Device {
    name: String,
    active: bool,
    alive: bool,
}

#[derive(Default)]
struct State {
    devices: HashMap<ClientHandle, Device>,
    controlling: Option<ClientHandle>,
}

impl State {
    /// Sharing is paused: every device switched off.
    fn paused(&self) -> bool {
        !self.devices.is_empty() && self.devices.values().all(|d| !d.active)
    }

    fn status(&self) -> String {
        if let Some(device) = self.controlling.and_then(|h| self.devices.get(&h)) {
            return format!("Keyboard and mouse on {}", device.name);
        }
        if self.paused() {
            return "Sharing is paused".to_owned();
        }
        if let Some(device) = self.devices.values().find(|d| d.alive) {
            return format!("Connected to {}", device.name);
        }
        match self.devices.values().next() {
            Some(device) => format!("Looking for {}…", device.name),
            None => "No computer paired".to_owned(),
        }
    }
}

pub struct Menu {
    state: Rc<RefCell<State>>,
}

/// The menu follows the service's events from now on; "Pause sharing"
/// switches every device off, "Resume sharing" on again.
pub fn track(window: &Window) -> Menu {
    let state = Rc::new(RefCell::new(State::default()));
    let weak = window.downgrade();
    let handler_state = state.clone();
    macos_status_item::on_pause(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let state = handler_state.borrow();
        let resume = state.paused();
        for &handle in state.devices.keys() {
            window.request(FrontendRequest::Activate(handle, resume));
        }
    });
    Menu { state }
}

impl Menu {
    pub fn event(&self, event: &FrontendEvent) {
        let mut state = self.state.borrow_mut();
        match event {
            FrontendEvent::Created(handle, config, s) | FrontendEvent::State(handle, config, s) => {
                state.devices.insert(
                    *handle,
                    device(config.hostname.as_deref(), s.active, s.alive),
                );
            }
            FrontendEvent::Enumerate(clients) => {
                state.devices = clients
                    .iter()
                    .map(|(h, c, s)| (*h, device(c.hostname.as_deref(), s.active, s.alive)))
                    .collect();
            }
            FrontendEvent::Deleted(handle) => {
                state.devices.remove(handle);
            }
            FrontendEvent::Controlling(handle) => state.controlling = *handle,
            _ => return,
        }
        macos_status_item::set_status(&state.status(), state.paused());
    }
}

fn device(hostname: Option<&str>, active: bool, alive: bool) -> Device {
    let name = hostname
        .unwrap_or("a computer")
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_owned();
    Device {
        name,
        active,
        alive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_says_what_matters_most() {
        let mut state = State::default();
        assert_eq!(state.status(), "No computer paired");
        state
            .devices
            .insert(0, device(Some("omarchy.local"), true, false));
        assert_eq!(state.status(), "Looking for omarchy…");
        state.devices.get_mut(&0).unwrap().alive = true;
        assert_eq!(state.status(), "Connected to omarchy");
        state.controlling = Some(0);
        assert_eq!(state.status(), "Keyboard and mouse on omarchy");
        state.controlling = None;
        state.devices.get_mut(&0).unwrap().active = false;
        assert!(state.paused());
        assert_eq!(state.status(), "Sharing is paused");
    }
}
