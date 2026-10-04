use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Display,
    mem::swap,
    task::{Poll, ready},
};

use async_trait::async_trait;
use futures::StreamExt;
use futures_core::Stream;

use input_event::{Event, KeyboardEvent, scancode};

pub use error::{CaptureCreationError, CaptureError, InputCaptureError};

pub mod error;

mod desktop;
pub use desktop::{DesktopBounds, desktop_bounds, displays};

#[cfg(libei)]
mod libei;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_drag;

/// Marks events Lan Mouse posts on this device for itself (in the event's
/// source user data, macOS): capture lets them through to the local system
/// instead of sending them to the device being controlled.
pub const LOCAL_EVENT_MARKER: i64 = 0x4c4d_4f55_5345; // "LMOUSE"

/// The files of a drag in progress on this device (with the left button
/// held for it), where the platform shows them to other processes.
#[cfg(target_os = "macos")]
pub use macos_drag::{current_drag, end_drag_where_it_started};

#[cfg(layer_shell)]
mod wayland_drag;

/// The files of a drag that reached an edge to another device (Wayland).
#[cfg(layer_shell)]
pub use wayland_drag::{current_drag, drag_pending};

/// Whether a dragged file list is still on its way: never here.
#[cfg(not(layer_shell))]
pub fn drag_pending() -> bool {
    false
}

/// The files of a drag in progress on this device: not readable here.
#[cfg(not(any(target_os = "macos", layer_shell)))]
pub fn current_drag() -> Option<Vec<std::path::PathBuf>> {
    None
}

/// Watch these screen edges (where other devices are) for dragged files.
#[cfg(layer_shell)]
pub use wayland_drag::watch_edges as watch_drag_edges;

/// Watch these screen edges for dragged files: not needed (macOS reads the
/// drag pasteboard) or not possible here.
#[cfg(not(layer_shell))]
pub fn watch_drag_edges(_edges: Vec<Position>) {}

/// End a drag carried to another device: nothing to do here.
#[cfg(not(target_os = "macos"))]
pub fn end_drag_where_it_started() {}

#[cfg(layer_shell)]
mod layer_shell;

#[cfg(windows)]
mod windows;

#[cfg(x11)]
mod x11;

/// fallback input capture (does not produce events)
mod dummy;

pub type CaptureHandle = u64;

/// Where `value` lies between `start` and `end` of an edge, scaled to
/// `0..=u16::MAX` for [`CaptureEvent::Begin`].
pub fn edge_fraction(value: f64, start: f64, end: f64) -> u16 {
    if end <= start {
        return 0;
    }
    let t = ((value - start) / (end - start)).clamp(0.0, 1.0);
    (t * u16::MAX as f64).round() as u16
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CaptureEvent {
    /// capture on this capture handle is now active.
    /// `along` is where the cursor crossed the edge, see [`edge_fraction`];
    /// `None` if the backend doesn't know.
    Begin { along: Option<u16> },
    /// input event coming from capture handle
    Input(Event),
}

impl Display for CaptureEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureEvent::Begin { .. } => write!(f, "begin capture"),
            CaptureEvent::Input(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Position {
    Left,
    Right,
    Top,
    Bottom,
}

impl Position {
    pub fn opposite(&self) -> Self {
        match self {
            Position::Left => Self::Right,
            Position::Right => Self::Left,
            Position::Top => Self::Bottom,
            Position::Bottom => Self::Top,
        }
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pos = match self {
            Position::Left => "left",
            Position::Right => "right",
            Position::Top => "top",
            Position::Bottom => "bottom",
        };
        write!(f, "{pos}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    #[cfg(libei)]
    InputCapturePortal,
    #[cfg(layer_shell)]
    LayerShell,
    #[cfg(x11)]
    X11,
    #[cfg(windows)]
    Windows,
    #[cfg(target_os = "macos")]
    MacOs,
    Dummy,
}

impl Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(libei)]
            Backend::InputCapturePortal => write!(f, "input-capture-portal"),
            #[cfg(layer_shell)]
            Backend::LayerShell => write!(f, "layer-shell"),
            #[cfg(x11)]
            Backend::X11 => write!(f, "X11"),
            #[cfg(windows)]
            Backend::Windows => write!(f, "windows"),
            #[cfg(target_os = "macos")]
            Backend::MacOs => write!(f, "MacOS"),
            Backend::Dummy => write!(f, "dummy"),
        }
    }
}

pub struct InputCapture {
    /// capture backend
    capture: Box<dyn Capture>,
    /// keys pressed by active capture
    pressed_keys: HashSet<scancode::Linux>,
    /// map from position to ids
    position_map: HashMap<Position, Vec<CaptureHandle>>,
    /// map from id to position
    id_map: HashMap<CaptureHandle, Position>,
    /// pending events
    pending: VecDeque<(CaptureHandle, CaptureEvent)>,
}

impl InputCapture {
    /// create a new client with the given id
    pub async fn create(&mut self, id: CaptureHandle, pos: Position) -> Result<(), CaptureError> {
        assert!(!self.id_map.contains_key(&id));

        self.id_map.insert(id, pos);

        if let Some(v) = self.position_map.get_mut(&pos) {
            v.push(id);
            Ok(())
        } else {
            self.position_map.insert(pos, vec![id]);
            self.capture.create(pos).await
        }
    }

    /// destroy the client with the given id, if it exists
    pub async fn destroy(&mut self, id: CaptureHandle) -> Result<(), CaptureError> {
        let pos = self
            .id_map
            .remove(&id)
            .expect("no position for this handle");

        log::debug!("destroying capture {id} @ {pos}");
        let remaining = self.position_map.get_mut(&pos).expect("id vector");
        remaining.retain(|&i| i != id);

        log::debug!("remaining ids @ {pos}: {remaining:?}");
        if remaining.is_empty() {
            log::debug!("destroying capture @ {pos} - no remaining ids");
            self.position_map.remove(&pos);
            self.capture.destroy(pos).await?;
        }
        Ok(())
    }

    /// release mouse
    pub async fn release(&mut self) -> Result<(), CaptureError> {
        self.pressed_keys.clear();
        self.capture.release().await
    }

    /// Drain and return every key the capture has forwarded as
    /// down-but-not-up. The caller is expected to synthesize key-up
    /// events to the remote peer for each — otherwise the peer
    /// retains phantom-held keys after capture is released. The
    /// canonical case is the release-bind chord
    /// (Ctrl+Shift+Alt+Meta): the down events were sent while
    /// capture was active, but the matching up events arrive after
    /// the local tap has flipped to passthrough and never reach
    /// the peer.
    pub fn take_pressed_keys(&mut self) -> HashSet<scancode::Linux> {
        std::mem::take(&mut self.pressed_keys)
    }

    /// destroy the input capture
    pub async fn terminate(&mut self) -> Result<(), CaptureError> {
        self.capture.terminate().await
    }

    /// creates a new [`InputCapture`]
    pub async fn new(backend: Option<Backend>) -> Result<Self, CaptureCreationError> {
        let capture = create(backend).await?;
        Ok(Self {
            capture,
            id_map: Default::default(),
            pending: Default::default(),
            position_map: Default::default(),
            pressed_keys: HashSet::new(),
        })
    }

    /// check whether the given keys are pressed
    pub fn keys_pressed(&self, keys: &[scancode::Linux]) -> bool {
        keys.iter().all(|k| self.pressed_keys.contains(k))
    }

    fn update_pressed_keys(&mut self, key: u32, state: u8) {
        if let Ok(scancode) = scancode::Linux::try_from(key) {
            log::debug!("key: {key}, state: {state}, scancode: {scancode:?}");
            match state {
                1 => self.pressed_keys.insert(scancode),
                _ => self.pressed_keys.remove(&scancode),
            };
        }
    }
}

impl Stream for InputCapture {
    type Item = Result<(CaptureHandle, CaptureEvent), CaptureError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        if let Some(e) = self.pending.pop_front() {
            return Poll::Ready(Some(Ok(e)));
        }

        // Events for a position nobody captures any more (a client was
        // just removed) are dropped. Keep polling then: returning Pending
        // after the backend returned an event would leave no wakeup
        // registered, and capture would stall until something else woke
        // the task (on an idle machine: never).
        let (pos, event) = loop {
            // ready
            let event = ready!(self.capture.poll_next_unpin(cx));

            // stream closed
            let event = match event {
                Some(e) => e,
                None => return Poll::Ready(None),
            };

            // error occurred
            let (pos, event) = match event {
                Ok(e) => e,
                Err(e) => return Poll::Ready(Some(Err(e))),
            };

            // handle key presses
            if let CaptureEvent::Input(Event::Keyboard(KeyboardEvent::Key { key, state, .. })) =
                event
            {
                self.update_pressed_keys(key, state);
            }

            if self.position_map.contains_key(&pos) {
                break (pos, event);
            }
            log::debug!("dropping {event:?} @ {pos}: nothing captures there");
        };

        let len = self
            .position_map
            .get(&pos)
            .map(|ids| ids.len())
            .unwrap_or(0);

        match len {
            0 => unreachable!("checked above"),
            1 => Poll::Ready(Some(Ok((
                self.position_map.get(&pos).expect("no id")[0],
                event,
            )))),
            _ => {
                let mut position_map = HashMap::new();
                swap(&mut self.position_map, &mut position_map);
                {
                    for &id in position_map.get(&pos).expect("position") {
                        self.pending.push_back((id, event));
                    }
                }
                swap(&mut self.position_map, &mut position_map);

                Poll::Ready(Some(Ok(self.pending.pop_front().expect("event"))))
            }
        }
    }
}

#[async_trait]
trait Capture: Stream<Item = Result<(Position, CaptureEvent), CaptureError>> + Unpin {
    /// create a new client with the given id
    async fn create(&mut self, pos: Position) -> Result<(), CaptureError>;

    /// destroy the client with the given id, if it exists
    async fn destroy(&mut self, pos: Position) -> Result<(), CaptureError>;

    /// release mouse
    async fn release(&mut self) -> Result<(), CaptureError>;

    /// destroy the input capture
    async fn terminate(&mut self) -> Result<(), CaptureError>;
}

async fn create_backend(
    backend: Backend,
) -> Result<
    Box<dyn Capture<Item = Result<(Position, CaptureEvent), CaptureError>>>,
    CaptureCreationError,
> {
    match backend {
        #[cfg(libei)]
        Backend::InputCapturePortal => Ok(Box::new(libei::LibeiInputCapture::new().await?)),
        #[cfg(layer_shell)]
        Backend::LayerShell => Ok(Box::new(layer_shell::LayerShellInputCapture::new()?)),
        #[cfg(x11)]
        Backend::X11 => Ok(Box::new(x11::X11InputCapture::new()?)),
        #[cfg(windows)]
        Backend::Windows => Ok(Box::new(windows::WindowsInputCapture::new())),
        #[cfg(target_os = "macos")]
        Backend::MacOs => Ok(Box::new(macos::MacOSInputCapture::new().await?)),
        Backend::Dummy => Ok(Box::new(dummy::DummyInputCapture::new())),
    }
}

async fn create(
    backend: Option<Backend>,
) -> Result<
    Box<dyn Capture<Item = Result<(Position, CaptureEvent), CaptureError>>>,
    CaptureCreationError,
> {
    if let Some(backend) = backend {
        let b = create_backend(backend).await;
        if b.is_ok() {
            log::info!("using capture backend: {backend}");
        }
        return b;
    }

    for backend in [
        #[cfg(libei)]
        Backend::InputCapturePortal,
        #[cfg(layer_shell)]
        Backend::LayerShell,
        #[cfg(x11)]
        Backend::X11,
        #[cfg(windows)]
        Backend::Windows,
        #[cfg(target_os = "macos")]
        Backend::MacOs,
    ] {
        match create_backend(backend).await {
            Ok(b) => {
                log::info!("using capture backend: {backend}");
                return Ok(b);
            }
            Err(e) if e.cancelled_by_user() => return Err(e),
            Err(e) => log::warn!("{backend} input capture backend unavailable: {e}"),
        }
    }
    Err(CaptureCreationError::NoAvailableBackend)
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use futures::task::noop_waker;
    use std::{pin::Pin, task::Context};

    /// A backend that yields queued events, then waits.
    struct Queued(VecDeque<(Position, CaptureEvent)>);

    impl Stream for Queued {
        type Item = Result<(Position, CaptureEvent), CaptureError>;
        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.0.pop_front() {
                Some(e) => Poll::Ready(Some(Ok(e))),
                None => Poll::Pending,
            }
        }
    }

    #[async_trait]
    impl Capture for Queued {
        async fn create(&mut self, _: Position) -> Result<(), CaptureError> {
            Ok(())
        }
        async fn destroy(&mut self, _: Position) -> Result<(), CaptureError> {
            Ok(())
        }
        async fn release(&mut self) -> Result<(), CaptureError> {
            Ok(())
        }
        async fn terminate(&mut self) -> Result<(), CaptureError> {
            Ok(())
        }
    }

    #[test]
    fn events_for_removed_clients_dont_stall_capture() {
        let begin = CaptureEvent::Begin { along: None };
        let mut capture = InputCapture {
            capture: Box::new(Queued(VecDeque::from([
                // the client on the left was just removed
                (Position::Left, begin),
                (Position::Right, begin),
            ]))),
            pressed_keys: HashSet::new(),
            position_map: HashMap::from([(Position::Right, vec![7])]),
            id_map: HashMap::from([(7, Position::Right)]),
            pending: VecDeque::new(),
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match Pin::new(&mut capture).poll_next(&mut cx) {
            Poll::Ready(Some(Ok((7, CaptureEvent::Begin { .. })))) => {}
            other => panic!("the event for the client on the right was held back: {other:?}"),
        }
    }
}
