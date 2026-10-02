use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    time::{Duration, Instant},
};

use futures::StreamExt;
use input_capture::{
    CaptureError, CaptureEvent, CaptureHandle, InputCapture, InputCaptureError, Position,
};
use input_event::{Event, KeyboardEvent, PointerEvent, scancode};
use lan_mouse_proto::ProtoEvent;
use local_channel::mpsc::{Receiver, Sender, channel};
use tokio::task::{JoinHandle, spawn_local};
use tokio_util::sync::CancellationToken;

use crate::connect::LanMouseConnection;

pub(crate) struct Capture {
    cancellation_token: CancellationToken,
    request_tx: Sender<CaptureRequest>,
    task: JoinHandle<()>,
    event_rx: Receiver<ICaptureEvent>,
}

pub(crate) enum ICaptureEvent {
    /// a client was entered
    CaptureBegin(CaptureHandle),
    /// capture disabled
    CaptureDisabled,
    /// capture disabled
    CaptureEnabled,
    /// A (new) client was entered.
    /// In contrast to [`ICaptureEvent::CaptureBegin`] this
    /// event is only triggered when the capture was
    /// explicitly released in the meantime by
    /// either the remote client leaving its device region,
    /// a new device entering the screen or the release bind.
    ClientEntered(u64),
    /// The previously active client was left, i.e. capture
    /// was released for the given handle. Mirrors
    /// [`ICaptureEvent::ClientEntered`] for the leave side
    /// and fires on every release path (release-bind chord,
    /// remote `Leave`, explicit `Release` request, send
    /// failure, or destroy of the active capture).
    ClientLeft(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CaptureType {
    /// a normal input capture
    Default,
    /// A capture only interested in [`CaptureEvent::Begin`] events.
    /// The capture is released immediately, if there is no
    /// Default capture at the same position.
    EnterOnly,
}

#[derive(Clone, Debug)]
enum CaptureRequest {
    /// capture must release the mouse
    Release,
    /// add a capture client
    Create(CaptureHandle, Position, CaptureType),
    /// destory a capture client
    Destroy(CaptureHandle),
    /// reenable input capture
    Reenable,
    /// set release bind
    SetReleaseBind(Vec<scancode::Linux>),
}

impl Capture {
    pub(crate) fn new(
        backend: Option<input_capture::Backend>,
        conn: LanMouseConnection,
        release_bind: Vec<scancode::Linux>,
    ) -> Self {
        let (request_tx, request_rx) = channel();
        let (event_tx, event_rx) = channel();
        let cancellation_token = CancellationToken::new();
        let capture_task = CaptureTask {
            active_client: None,
            backend,
            cancellation_token: cancellation_token.clone(),
            captures: Default::default(),
            conn,
            last_send_failure: Default::default(),
            desktop: Default::default(),
            entry_along: None,
            crossing: 0,
            pushing: None,
            event_tx,
            request_rx,
            release_bind: Rc::new(RefCell::new(release_bind)),
            state: Default::default(),
        };
        let task = spawn_local(capture_task.run());
        Self {
            cancellation_token,
            request_tx,
            task,
            event_rx,
        }
    }

    pub(crate) fn reenable(&self) {
        self.request_tx
            .send(CaptureRequest::Reenable)
            .expect("channel closed");
    }

    pub(crate) async fn terminate(&mut self) {
        self.cancellation_token.cancel();
        log::debug!("terminating capture");
        if let Err(e) = (&mut self.task).await {
            log::warn!("{e}");
        }
    }

    pub(crate) fn create(
        &self,
        handle: CaptureHandle,
        pos: lan_mouse_ipc::Position,
        capture_type: CaptureType,
    ) {
        let pos = to_capture_pos(pos);
        self.request_tx
            .send(CaptureRequest::Create(handle, pos, capture_type))
            .expect("channel closed");
    }

    pub(crate) fn destroy(&self, handle: CaptureHandle) {
        self.request_tx
            .send(CaptureRequest::Destroy(handle))
            .expect("channel closed");
    }

    pub(crate) fn release(&self) {
        self.request_tx
            .send(CaptureRequest::Release)
            .expect("channel closed");
    }

    pub(crate) async fn event(&mut self) -> ICaptureEvent {
        self.event_rx.recv().await.expect("channel closed")
    }

    pub(crate) fn set_release_bind(&mut self, bind: Vec<scancode::Linux>) {
        let _ = self.request_tx.send(CaptureRequest::SetReleaseBind(bind));
    }
}

/// debounce a statement `$st`, i.e. the statement is executed only if the
/// time since the previous execution is at least `$dur`.
/// `$prev` is used to keep track of this timestamp
macro_rules! debounce {
    ($prev:ident, $dur:expr, $st:stmt) => {
        let exec = match $prev.get() {
            None => true,
            Some(instant) if instant.elapsed() > $dur => true,
            _ => false,
        };
        if exec {
            $prev.replace(Some(Instant::now()));
            $st
        }
    };
}

/// How long to ignore new crossings after sending to a client failed.
const RETRY_COOLDOWN: Duration = Duration::from_millis(500);

struct CaptureTask {
    active_client: Option<CaptureHandle>,
    backend: Option<input_capture::Backend>,
    cancellation_token: CancellationToken,
    captures: Vec<(CaptureHandle, Position, CaptureType)>,
    conn: LanMouseConnection,
    /// this desktop's bounds and when they were measured, see
    /// [`CaptureTask::local_desktop`]
    desktop: RefCell<Option<(Instant, input_capture::DesktopBounds)>>,
    /// when sending to each client last failed, see [`RETRY_COOLDOWN`]
    last_send_failure: HashMap<CaptureHandle, Instant>,
    /// where the cursor crossed into the active client, re-sent with every `Enter`
    entry_along: Option<u16>,
    /// numbers crossings, see [`ProtoEvent::CursorPosition`]
    crossing: u16,
    /// the pointer reached an edge and must push on to cross, see [`Push`]
    pushing: Option<Push>,
    event_tx: Sender<ICaptureEvent>,
    release_bind: Rc<RefCell<Vec<scancode::Linux>>>,
    request_rx: Receiver<CaptureRequest>,
    state: State,
}

impl CaptureTask {
    fn add_capture(&mut self, handle: CaptureHandle, pos: Position, capture_type: CaptureType) {
        self.captures.push((handle, pos, capture_type));
    }

    fn remove_capture(&mut self, handle: CaptureHandle) {
        self.captures.retain(|&(h, ..)| handle != h);
    }

    fn is_default_capture_at(&self, pos: Position) -> bool {
        self.captures
            .iter()
            .any(|&(_, p, t)| p == pos && t == CaptureType::Default)
    }

    fn get_pos(&self, handle: CaptureHandle) -> Position {
        self.captures
            .iter()
            .find(|(h, ..)| *h == handle)
            .expect("no such capture")
            .1
    }

    fn get_type(&self, handle: CaptureHandle) -> CaptureType {
        self.captures
            .iter()
            .find(|(h, ..)| *h == handle)
            .expect("no such capture")
            .2
    }

    async fn run(mut self) {
        // Capture can stop on its own, e.g. macOS turns event taps off
        // while a password field is focused (the lock screen after
        // sleep). Nobody may be around to re-enable it by hand, so try
        // again by ourselves, backing off while it keeps failing.
        const RETRY: [u64; 5] = [2, 5, 10, 30, 60];
        let mut failures = 0;
        loop {
            let started = Instant::now();
            if let Err(e) = self.do_capture().await {
                log::warn!("input capture exited: {e}");
            }
            if self.cancellation_token.is_cancelled() {
                return;
            }
            // a session that ran for a while was fine: start over quickly
            if started.elapsed() > Duration::from_secs(60) {
                failures = 0;
            }
            let wait = Duration::from_secs(RETRY[failures.min(RETRY.len() - 1)]);
            failures += 1;
            log::info!("restarting input capture in {}s", wait.as_secs());
            let retry = tokio::time::sleep(wait);
            tokio::pin!(retry);
            loop {
                tokio::select! {
                    _ = &mut retry => break,
                    r = self.request_rx.recv() => match r.expect("channel closed") {
                        CaptureRequest::Reenable => break,
                        CaptureRequest::Create(h, p, t) => self.add_capture(h, p, t),
                        CaptureRequest::Destroy(h) => self.remove_capture(h),
                        CaptureRequest::Release => { /* nothing to do */ }
                        CaptureRequest::SetReleaseBind(bind) => {
                            self.release_bind.borrow_mut().clone_from(&bind);
                        }
                    },
                    _ = self.cancellation_token.cancelled() => return,
                }
            }
        }
    }

    async fn do_capture(&mut self) -> Result<(), InputCaptureError> {
        /* allow cancelling capture request */
        let mut capture = tokio::select! {
            r = InputCapture::new(self.backend) => r?,
            _ = self.cancellation_token.cancelled() => return Ok(()),
        };

        let _capture_guard = DropGuard::new(
            self.event_tx.clone(),
            ICaptureEvent::CaptureEnabled,
            ICaptureEvent::CaptureDisabled,
        );

        /* create barriers for active clients */
        let r = self.create_captures(&mut capture).await;
        if let Err(e) = r {
            capture.terminate().await?;
            return Err(e.into());
        }

        let r = self.do_capture_session(&mut capture).await;

        // FIXME replace with async drop when stabilized
        capture.terminate().await?;

        r
    }

    async fn create_captures(&mut self, capture: &mut InputCapture) -> Result<(), CaptureError> {
        let captures = self.captures.clone();
        for (handle, pos, _type) in captures {
            tokio::select! {
                r = capture.create(handle, pos) => r?,
                _ = self.cancellation_token.cancelled() => return Ok(()),
            }
        }
        Ok(())
    }

    async fn do_capture_session(
        &mut self,
        capture: &mut InputCapture,
    ) -> Result<(), InputCaptureError> {
        loop {
            tokio::select! {
                event = capture.next() => match event {
                    Some(event) => self.handle_capture_event(capture, event?).await?,
                    None => return Ok(()),
                },
                (handle, event) = self.conn.recv() => {
                    if let Some(active) = self.active_client {
                        if handle != active {
                            // we only care about events coming from the client we are currently connected to
                            // only `Ack` and `Leave` are relevant
                            continue
                        }
                    }

                    match event {
                        // connection acknowlegded => set state to Sending
                        ProtoEvent::Ack(_) => {
                            log::info!("client {handle} acknowledged the connection!");
                            self.state = State::Sending;
                        }
                        // client disconnected
                        ProtoEvent::Leave(_) => {
                            log::info!("releasing capture: left remote client device region");
                            self.release_capture(capture).await?;
                        },
                        _ => {}
                    }
                },
                e = self.request_rx.recv() => match e.expect("channel closed") {
                    CaptureRequest::Reenable => { /* already active */ },
                    CaptureRequest::Release => self.release_capture(capture).await?,
                    CaptureRequest::Create(h, p, t) => {
                        self.add_capture(h, p, t);
                        capture.create(h, p).await?;
                    }
                    CaptureRequest::Destroy(h) => {
                        // If the capture we're tearing down is the
                        // currently-active one, treat this as a
                        // release for hook purposes. The release_capture
                        // path also clears active_client and flushes
                        // pressed-key state to the peer; without this,
                        // `cli deactivate` (or a hostname change
                        // re-creating the client) would skip leave_hook.
                        if self.active_client == Some(h) {
                            self.release_capture(capture).await?;
                        }
                        self.remove_capture(h);
                        capture.destroy(h).await?;
                    }
                    CaptureRequest::SetReleaseBind(bind) => {
                        self.release_bind.borrow_mut().clone_from(&bind);
                    }
                },
                _ = self.cancellation_token.cancelled() => break,
            }
        }
        Ok(())
    }

    async fn handle_capture_event(
        &mut self,
        capture: &mut InputCapture,
        event: (CaptureHandle, CaptureEvent),
    ) -> Result<(), CaptureError> {
        let (handle, event) = event;
        log::trace!("({handle}): {event:?}");

        if capture.keys_pressed(&self.release_bind.borrow()) {
            log::info!("releasing capture: release-bind pressed");
            self.pushing = None;
            return self.release_capture(capture).await;
        }

        // Reaching the edge doesn't cross yet: the pointer has to push on,
        // so brushing the edge while moving along it stays on this screen.
        let event = if self.get_type(handle) == CaptureType::Default
            && self.active_client != Some(handle)
        {
            match self.push(handle, event) {
                PushOutcome::Cross(event) => event,
                PushOutcome::Wait => return Ok(()),
                PushOutcome::StayHere(slide) => {
                    log::debug!("not crossing: the pointer didn't push through the edge");
                    return capture.release_sliding(slide).await;
                }
            }
        } else {
            event
        };

        // While a client is unreachable, the cursor stays pressed against the
        // edge and re-triggers capture continuously. Don't retry (and fire the
        // enter hook) on every one of those until the cooldown has passed.
        if matches!(event, CaptureEvent::Begin { .. })
            && self
                .last_send_failure
                .get(&handle)
                .is_some_and(|t| t.elapsed() < RETRY_COOLDOWN)
        {
            return capture.release().await;
        }

        if let CaptureEvent::Begin { along } = event {
            self.crossing = self.crossing.wrapping_add(1);
            self.entry_along = if self.get_type(handle) == CaptureType::Default {
                match self.map_crossing(handle, along) {
                    Some(along) => along,
                    // outside the other screen: stay on this one
                    None => return capture.release().await,
                }
            } else {
                along
            };
            self.event_tx
                .send(ICaptureEvent::CaptureBegin(handle))
                .expect("channel closed");
        }

        // enter only capture (for incoming connections)
        if self.get_type(handle) == CaptureType::EnterOnly {
            // if there is no active outgoing connection at the current capture,
            // we release the capture
            if !self.is_default_capture_at(self.get_pos(handle)) {
                log::info!("releasing capture: no active client at this position");
                capture.release().await?;
            }
            // we dont care about events from incoming handles except for releasing the capture
            return Ok(());
        }

        // activated a new client
        if matches!(event, CaptureEvent::Begin { .. }) && Some(handle) != self.active_client {
            self.state = State::WaitingForAck;
            self.active_client.replace(handle);
            self.event_tx
                .send(ICaptureEvent::ClientEntered(handle))
                .expect("channel closed");
        }

        let opposite_pos = to_proto_pos(self.get_pos(handle).opposite());

        let event = match event {
            CaptureEvent::Begin { .. } => ProtoEvent::Enter(opposite_pos),
            CaptureEvent::Input(e) => match self.state {
                // connection not acknowledged, repeat `Enter` event
                State::WaitingForAck => ProtoEvent::Enter(opposite_pos),
                State::Sending => ProtoEvent::Input(e),
            },
        };

        let mut result = self.conn.send(event, handle).await;
        if let (ProtoEvent::Enter(pos), Some(along), Ok(())) = (event, self.entry_along, &result) {
            result = self
                .conn
                .send(
                    ProtoEvent::CursorPosition {
                        pos,
                        along,
                        crossing: self.crossing,
                    },
                    handle,
                )
                .await;
        }

        if let Err(e) = result {
            self.last_send_failure.insert(handle, Instant::now());
            const DUR: Duration = Duration::from_millis(500);
            debounce!(PREV_LOG, DUR, log::warn!("releasing capture: {e}"));
            // Funnel through release_capture so the leave_hook
            // fires and active_client is cleared (without this the
            // active_client field would stay stale until the next
            // Begin from a different handle).
            self.release_capture(capture).await?;
        }
        Ok(())
    }

    /// Where a crossing at `along` (a fraction of this desktop's edge) lands
    /// on the client's screen, as a fraction of its edge. `Some(None)` leaves
    /// the landing spot unknown; `None` means the crossing misses the other
    /// screen and must not happen.
    ///
    /// Without an arranged offset the edges map proportionally, top to top
    /// and bottom to bottom. With one, positions map pixel for pixel, as the
    /// screens are arranged.
    fn map_crossing(&self, handle: CaptureHandle, along: Option<u16>) -> Option<Option<u16>> {
        let arrangement = self.conn.client_manager().arrangement(handle);
        let (Some(along), Some(arrangement)) = (along, arrangement) else {
            return Some(along);
        };
        let (Some(offset), Some((peer_width, peer_height))) =
            (arrangement.offset, arrangement.peer_size)
        else {
            return Some(Some(along));
        };
        let pos = arrangement.pos;
        let Some(local) = self.local_desktop() else {
            return Some(Some(along));
        };
        let (local_len, peer_len) = match pos {
            lan_mouse_ipc::Position::Left | lan_mouse_ipc::Position::Right => {
                (local.height, peer_height)
            }
            lan_mouse_ipc::Position::Top | lan_mouse_ipc::Position::Bottom => {
                (local.width, peer_width)
            }
        };
        arranged_crossing(along, local_len, offset, peer_len)
    }

    /// This desktop's bounds. Measuring them talks to the compositor, and a
    /// refused crossing is retried on every pointer motion against the edge,
    /// so reuse a recent measurement.
    fn local_desktop(&self) -> Option<input_capture::DesktopBounds> {
        const FRESH: Duration = Duration::from_secs(5);
        if let Some((at, bounds)) = *self.desktop.borrow() {
            if at.elapsed() < FRESH {
                return Some(bounds);
            }
        }
        let bounds = input_capture::desktop_bounds()?;
        self.desktop.replace(Some((Instant::now(), bounds)));
        Some(bounds)
    }

    /// Decide what reaching the edge to client `handle` leads to, see [`Push`].
    fn push(&mut self, handle: CaptureHandle, event: CaptureEvent) -> PushOutcome {
        let pos = self.get_pos(handle);
        match (event, self.pushing.as_mut()) {
            (CaptureEvent::Begin { along }, _) => {
                self.pushing = Some(Push::new(handle, pos, along));
                PushOutcome::Wait
            }
            (CaptureEvent::Input(input), Some(push)) if push.handle == handle => {
                match push.update(&input) {
                    PushState::Through => {
                        let along = push.along;
                        self.pushing = None;
                        PushOutcome::Cross(CaptureEvent::Begin { along })
                    }
                    PushState::Pushing => PushOutcome::Wait,
                    PushState::Gave => {
                        let slide = push.slid;
                        self.pushing = None;
                        PushOutcome::StayHere(slide)
                    }
                }
            }
            // input while captured for another reason: nothing to cross into
            (CaptureEvent::Input(_), _) => PushOutcome::StayHere(0.0),
        }
    }

    async fn release_capture(&mut self, capture: &mut InputCapture) -> Result<(), CaptureError> {
        // If we have an active client, notify them we're leaving
        if let Some(handle) = self.active_client.take() {
            // Surface the leave to the service layer so it can fire
            // the per-client leave_hook. Sent before the network
            // teardown below so we never race against the peer
            // disappearing.
            self.event_tx
                .send(ICaptureEvent::ClientLeft(handle))
                .expect("channel closed");
            // Synthesize key-up events for every key still held in the
            // capture's pressed_keys set BEFORE sending Leave. Without
            // this, pressing the release-bind chord (typically all four
            // modifiers) leaves the peer with phantom held modifiers:
            // the down events were forwarded while capture was active,
            // but the matching up events arrive after the local tap
            // flips to passthrough and never reach the peer. The peer
            // then runs every subsequent keystroke through those held
            // mods until its watchdog times out (1+ s) or our Leave
            // arrives — and Leave can be lost over UDP/DTLS.
            for key in capture.take_pressed_keys() {
                let key_up = ProtoEvent::Input(Event::Keyboard(KeyboardEvent::Key {
                    time: 0,
                    key: key as u32,
                    state: 0,
                }));
                if let Err(e) = self.conn.send(key_up, handle).await {
                    log::warn!("failed to send key-up to client {handle}: {e}");
                }
            }
            // Reset the modifier mask too. The peer's input-emulation
            // layer keeps a separate XKB-style modifier state that's
            // updated by KeyboardEvent::Modifiers, distinct from the
            // pressed_keys set drained above. Without this, an
            // already-locked CapsLock would survive the release.
            let mods_zero = ProtoEvent::Input(Event::Keyboard(KeyboardEvent::Modifiers {
                depressed: 0,
                latched: 0,
                locked: 0,
                group: 0,
            }));
            if let Err(e) = self.conn.send(mods_zero, handle).await {
                log::warn!("failed to reset modifiers on client {handle}: {e}");
            }

            log::info!("sending Leave event to client {handle}");
            if let Err(e) = self.conn.send(ProtoEvent::Leave(0), handle).await {
                log::warn!("failed to send Leave to client {handle}: {e}");
            }
        }
        capture.release().await
    }
}

thread_local! {
    static PREV_LOG: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// How far the pointer has to keep moving into an edge to cross it, in
/// pointer motion units (about pixels).
const PUSH_DISTANCE: f64 = 30.0;
/// Pushing must make progress: past this, a pause or a slow drift stays.
const PUSH_TIMEOUT: Duration = Duration::from_millis(800);

/// The pointer reached the edge to another device. It crosses once it has
/// pushed [`PUSH_DISTANCE`] further into the edge; moving back, sliding
/// along the edge more than into it, or stalling keeps it on this screen,
/// where it slid to.
struct Push {
    handle: CaptureHandle,
    pos: input_capture::Position,
    /// where along the edge it arrived, see [`CaptureEvent::Begin`]
    along: Option<u16>,
    /// motion into the edge so far
    pushed: f64,
    /// motion along the edge so far
    slid: f64,
    since: Instant,
}

enum PushState {
    Pushing,
    Through,
    Gave,
}

enum PushOutcome {
    /// cross with this (`Begin`) event
    Cross(CaptureEvent),
    /// keep watching the pointer
    Wait,
    /// stay on this screen, this far along the edge from where it arrived
    StayHere(f64),
}

impl Push {
    fn new(handle: CaptureHandle, pos: input_capture::Position, along: Option<u16>) -> Self {
        Self {
            handle,
            pos,
            along,
            pushed: 0.0,
            slid: 0.0,
            since: Instant::now(),
        }
    }

    fn update(&mut self, input: &Event) -> PushState {
        let Event::Pointer(PointerEvent::Motion { dx, dy, .. }) = *input else {
            // a click or key at the edge: it's meant for this screen
            return PushState::Gave;
        };
        let (into, along) = match self.pos {
            input_capture::Position::Left => (-dx, dy),
            input_capture::Position::Right => (dx, dy),
            input_capture::Position::Top => (-dy, dx),
            input_capture::Position::Bottom => (dy, dx),
        };
        self.pushed += into;
        self.slid += along;
        if self.pushed >= PUSH_DISTANCE {
            PushState::Through
        } else if self.pushed < -2.0
            || self.slid.abs() > self.pushed.max(0.0) + 10.0
            || self.since.elapsed() > PUSH_TIMEOUT
        {
            PushState::Gave
        } else {
            PushState::Pushing
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    #[default]
    WaitingForAck,
    Sending,
}

fn to_capture_pos(pos: lan_mouse_ipc::Position) -> input_capture::Position {
    match pos {
        lan_mouse_ipc::Position::Left => input_capture::Position::Left,
        lan_mouse_ipc::Position::Right => input_capture::Position::Right,
        lan_mouse_ipc::Position::Top => input_capture::Position::Top,
        lan_mouse_ipc::Position::Bottom => input_capture::Position::Bottom,
    }
}

fn to_proto_pos(pos: input_capture::Position) -> lan_mouse_proto::Position {
    match pos {
        input_capture::Position::Left => lan_mouse_proto::Position::Left,
        input_capture::Position::Right => lan_mouse_proto::Position::Right,
        input_capture::Position::Top => lan_mouse_proto::Position::Top,
        input_capture::Position::Bottom => lan_mouse_proto::Position::Bottom,
    }
}

struct DropGuard<T> {
    tx: Sender<T>,
    on_drop: Option<T>,
}

impl<T> DropGuard<T> {
    fn new(tx: Sender<T>, on_new: T, on_drop: T) -> Self {
        tx.send(on_new).expect("channel closed");
        let on_drop = Some(on_drop);
        Self { tx, on_drop }
    }
}

impl<T> Drop for DropGuard<T> {
    fn drop(&mut self) {
        self.tx
            .send(self.on_drop.take().expect("item"))
            .expect("channel closed");
    }
}

/// Pixel-exact mapping of a crossing at `along` (fraction of a local edge of
/// `local_len` pixels) onto a screen whose edge starts `offset` pixels along
/// ours and is `peer_len` long. `None` if the crossing misses that screen.
fn arranged_crossing(
    along: u16,
    local_len: u32,
    offset: i32,
    peer_len: u32,
) -> Option<Option<u16>> {
    let local_px = along as f64 / u16::MAX as f64 * local_len as f64;
    let peer_px = local_px - offset as f64;
    if peer_px < 0.0 || peer_px >= peer_len as f64 {
        return None;
    }
    Some(Some(input_capture::edge_fraction(
        peer_px,
        0.0,
        peer_len as f64,
    )))
}

#[cfg(test)]
mod tests {
    use super::{Push, PushState, arranged_crossing};
    use input_event::{Event, PointerEvent};

    fn motion(dx: f64, dy: f64) -> Event {
        Event::Pointer(PointerEvent::Motion { time: 0, dx, dy })
    }

    fn push_with(moves: &[(f64, f64)]) -> &'static str {
        let mut push = Push::new(0, input_capture::Position::Left, Some(100));
        for &(dx, dy) in moves {
            match push.update(&motion(dx, dy)) {
                PushState::Pushing => continue,
                PushState::Through => return "cross",
                PushState::Gave => return "stay",
            }
        }
        "waiting"
    }

    #[test]
    fn crossing_takes_a_push_through_the_edge() {
        // the device is on the left: pushing left crosses, once far enough
        assert_eq!(push_with(&[(-10.0, 0.0), (-10.0, 1.0)]), "waiting");
        assert_eq!(
            push_with(&[(-10.0, 0.0), (-10.0, 1.0), (-12.0, 0.0)]),
            "cross"
        );
        // a diagonal push still crosses
        assert_eq!(
            push_with(&[(-12.0, 8.0), (-12.0, 8.0), (-12.0, 8.0)]),
            "cross"
        );
        // sliding down along the edge stays here
        assert_eq!(push_with(&[(-1.0, 6.0), (-1.0, 6.0), (-1.0, 6.0)]), "stay");
        // so does moving back
        assert_eq!(push_with(&[(-5.0, 0.0), (8.0, 0.0)]), "stay");
        // and a click
        let mut push = Push::new(0, input_capture::Position::Right, None);
        let click = Event::Pointer(PointerEvent::Button {
            time: 0,
            button: 272,
            state: 1,
        });
        assert!(matches!(push.update(&click), PushState::Gave));
    }

    fn fraction(f: f64) -> u16 {
        (f * u16::MAX as f64).round() as u16
    }

    #[test]
    fn arranged_crossings_line_up_pixel_for_pixel() {
        // a 900px screen whose top sits 100px below the top of our 768px edge
        let landing = arranged_crossing(fraction(0.5), 768, 100, 900).expect("hits");
        // 384px down our edge is 284px down theirs
        let expected = fraction(284.0 / 900.0);
        assert!(landing.unwrap().abs_diff(expected) <= 1);
    }

    #[test]
    fn crossings_outside_the_other_screen_are_refused() {
        // their screen starts 100px down: the top 100px of our edge lead nowhere
        assert_eq!(arranged_crossing(fraction(0.05), 768, 100, 900), None);
        // a small screen ending 300px down: below that too
        assert_eq!(arranged_crossing(fraction(0.9), 768, 0, 300), None);
        // a screen above ours (negative offset) overlapping its top part
        assert!(arranged_crossing(fraction(0.1), 768, -500, 900).is_some());
    }
}
