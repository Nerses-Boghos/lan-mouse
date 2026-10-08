use crate::{
    capture::{Capture, CaptureType, ICaptureEvent},
    client::ClientManager,
    config::{Config, ConfigClient},
    connect::LanMouseConnection,
    control::{Control, ControlEvent, Destination, Layout, PairReply, PairRequest},
    crypto, diagnostics,
    discovery::{self, Discovery},
    dns::{DnsEvent, DnsResolver},
    drag,
    emulation::{Emulation, EmulationEvent},
    exit_shortcut::Shortcut,
    listen::{LanMouseListener, ListenerCreationError},
    update,
};
use futures::StreamExt;
use lan_mouse_ipc::{
    AsyncFrontendListener, ClientHandle, FrontendEvent, FrontendRequest, IpcError,
    IpcListenerCreationError, Monitor, PairStatus, Position, Status, TransferState, TransferUpdate,
};
use log;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    process::Command,
    signal,
    sync::{Notify, oneshot},
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    IpcListen(#[from] IpcListenerCreationError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    ListenError(#[from] ListenerCreationError),
    #[error("failed to load certificate: `{0}`")]
    Certificate(#[from] crypto::Error),
}

pub struct Service {
    /// configuration
    config: Config,
    /// input capture
    capture: Capture,
    /// input emulation
    emulation: Emulation,
    /// dns resolver
    resolver: DnsResolver,
    /// frontend listener
    frontend_listener: AsyncFrontendListener,
    /// authorized public key sha256 fingerprints
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    /// control channel for clipboard and pairing (if the port could be bound)
    control: Option<Control>,
    /// local network discovery (if mDNS is available)
    discovery: Option<Discovery>,
    /// this device's display name, as announced to others
    name: String,
    /// the `.local` host name other devices reach this one under
    hostname: String,
    /// pairing requests waiting for the user's answer, by fingerprint
    pending_pairs: HashMap<String, PendingPair>,
    /// pairings this device started, by fingerprint: where the user's
    /// confirmation of the code goes
    outgoing_pairs: HashMap<String, oneshot::Sender<bool>>,
    /// (outgoing) client information
    client_manager: ClientManager,
    /// current port
    port: u16,
    /// the public key fingerprint for (D)TLS
    public_key_fingerprint: String,
    /// notify for pending frontend events
    frontend_event_pending: Notify,
    /// frontend events queued for sending
    pending_frontend_events: VecDeque<FrontendEvent>,
    /// status of input capture (enabled / disabled)
    capture_status: Status,
    /// status of input emulation (enabled / disabled)
    emulation_status: Status,
    /// keep track of registered connections to avoid duplicate barriers
    incoming_conns: HashSet<SocketAddr>,
    /// map from capture handle to connection info
    incoming_conn_info: HashMap<ClientHandle, Incoming>,
    next_trigger_handle: u64,
    /// connected clients that have our layout, by the address they got it at
    layout_sent: HashMap<ClientHandle, SocketAddr>,
    /// updates offered to paired devices: version, and when (see
    /// [`Service::offer_update`])
    update_offers: HashMap<String, (String, std::time::Instant)>,
    /// this device's monitors, as last sent to other devices
    monitors: Vec<Monitor>,
    /// the current visit to another device, for drags carried there
    visit: Option<Visit>,
    /// files of a drag that crossed before they were known, see
    /// [`Service::wait_for_dragged_files`]
    late_drag_tx: local_channel::mpsc::Sender<(ClientHandle, Vec<std::path::PathBuf>)>,
    late_drag_rx: local_channel::mpsc::Receiver<(ClientHandle, Vec<std::path::PathBuf>)>,
}

/// While the keyboard and mouse control another device: a file drag
/// carried there is dropped when the button is released there, and taken
/// back when the pointer returns with the button still held.
struct Visit {
    handle: ClientHandle,
    released: bool,
    /// the outcome of the drag, for its transfer
    drag: Option<tokio::sync::watch::Sender<Option<bool>>>,
}

/// Pairing requests waiting for an answer at the same time; more are declined.
const MAX_PENDING_PAIRS: usize = 3;
/// How long before offering a device the same update again.
const UPDATE_RETRY: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
struct PendingPair {
    request: PairRequest,
    code: String,
    reply: oneshot::Sender<PairReply>,
}

#[derive(Debug)]
struct Incoming {
    fingerprint: String,
    addr: SocketAddr,
    pos: Position,
}

impl Service {
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        let client_manager = ClientManager::default();
        for client in config.clients() {
            client_manager.add_with_config(client);
        }

        // load certificate
        let cert = crypto::load_or_generate_key_and_cert(config.cert_path())?;
        let public_key_fingerprint = crypto::certificate_fingerprint(&cert);

        // create frontend communication adapter, exit if already running
        let frontend_listener = AsyncFrontendListener::new().await?;

        let authorized_keys = Arc::new(RwLock::new(config.authorized_fingerprints()));
        // listener + connection
        let listener =
            LanMouseListener::new(config.port(), cert.clone(), authorized_keys.clone()).await?;
        let conn = LanMouseConnection::new(cert.clone(), client_manager.clone());
        let control = Control::new(
            config.port(),
            &cert,
            authorized_keys.clone(),
            config.clipboard(),
        )
        .await
        .inspect_err(|e| log::warn!("clipboard sync and pairing unavailable: {e}"))
        .ok();
        let name = config.name().unwrap_or_else(discovery::local_name);
        let hostname = discovery::local_hostname();
        let discovery = Discovery::new(&name, &hostname, config.port(), &public_key_fingerprint)
            .inspect_err(|e| log::warn!("local network discovery unavailable: {e}"))
            .ok();

        // input capture + emulation
        let capture_backend = config.capture_backend().map(|b| b.into());
        let capture = Capture::new(capture_backend, conn, config.active_exit_shortcut());
        let emulation_backend = config.emulation_backend().map(|b| b.into());
        let emulation = Emulation::new(emulation_backend, listener);

        // create dns resolver
        let resolver = DnsResolver::new()?;

        let port = config.port();
        let (late_drag_tx, late_drag_rx) = local_channel::mpsc::channel();
        let service = Self {
            config,
            capture,
            emulation,
            frontend_listener,
            resolver,
            authorized_keys,
            control,
            discovery,
            name,
            hostname,
            pending_pairs: Default::default(),
            outgoing_pairs: Default::default(),
            public_key_fingerprint,
            client_manager,
            frontend_event_pending: Default::default(),
            port,
            pending_frontend_events: Default::default(),
            capture_status: Default::default(),
            emulation_status: Default::default(),
            incoming_conn_info: Default::default(),
            incoming_conns: Default::default(),
            next_trigger_handle: 0,
            layout_sent: Default::default(),
            update_offers: Default::default(),
            monitors: local_monitors(),
            visit: None,
            late_drag_tx,
            late_drag_rx,
        };
        Ok(service)
    }

    pub async fn run(&mut self) -> Result<(), ServiceError> {
        let active = self.client_manager.active_clients();
        for handle in active.iter() {
            // small hack: `activate_client()` checks, if the client
            // is already active in client_manager and does not create a
            // capture barrier in that case so we have to deactivate it first
            self.client_manager.deactivate_client(*handle);
        }

        for handle in active {
            self.activate_client(handle);
        }

        self.forget_untrusted_clients();

        // monitors come and go; other devices draw and map ours
        let mut monitor_check = tokio::time::interval(Duration::from_secs(10));
        let mut checks = 0u32;

        loop {
            tokio::select! {
                request = self.frontend_listener.next() => self.handle_frontend_request(request),
                _ = self.frontend_event_pending.notified() => self.handle_frontend_pending().await,
                event = self.emulation.event() => self.handle_emulation_event(event),
                event = self.capture.event() => self.handle_capture_event(event),
                event = self.resolver.event() => self.handle_resolver_event(event),
                handles = self.client_manager.connection_changed() => {
                    for handle in handles {
                        self.broadcast_client(handle);
                        self.share_layout_on_connect(handle);
                        self.offer_update(handle);
                    }
                }
                _ = monitor_check.tick() => {
                    self.check_monitors();
                    checks += 1;
                    if checks.is_multiple_of(6) {
                        self.resolve_unconnected();
                    }
                }
                Some((handle, files)) = self.late_drag_rx.recv() => {
                    // still on that visit, and not dropped already
                    let carrying = self.visit.as_ref()
                        .is_some_and(|v| v.handle == handle && !v.released && v.drag.is_none());
                    if carrying {
                        self.carry_drag(handle, files);
                    }
                }
                event = next_control_event(&mut self.control) => self.handle_control_event(event),
                _ = discovery_changed(&mut self.discovery) => {
                    self.update_announced_ips();
                    self.broadcast_discovered();
                    // what it runs on may only be known now
                    for handle in self.client_manager.active_clients() {
                        self.offer_update(handle);
                    }
                }
                _ = self.config.changed() => self.handle_config_change(),
                reason = termination() => {
                    log::info!("stopping: {reason}");
                    break;
                }
            }
        }

        log::info!("terminating service ...");
        log::debug!("terminating capture ...");
        self.capture.terminate().await;
        log::debug!("terminating emulation ...");
        self.emulation.terminate().await;
        log::debug!("terminating dns resolver ...");
        self.resolver.terminate().await;
        if let Some(discovery) = &self.discovery {
            discovery.terminate();
        }

        Ok(())
    }

    fn handle_frontend_request(&mut self, request: Option<Result<FrontendRequest, IpcError>>) {
        let request = match request.expect("frontend listener closed") {
            Ok(r) => r,
            Err(e) => return log::error!("error receiving request: {e}"),
        };
        match request {
            FrontendRequest::Activate(handle, active) => {
                self.set_client_active(handle, active);
                self.save_config();
            }
            FrontendRequest::AuthorizeKey(desc, fp) => {
                self.add_authorized_key(desc, fp);
                self.save_config();
            }
            FrontendRequest::ChangePort(port) => self.change_port(port),
            FrontendRequest::Create => {
                self.add_client();
                self.save_config();
            }
            FrontendRequest::Delete(handle) => {
                self.remove_client(handle);
                self.save_config();
            }
            FrontendRequest::EnableCapture => self.capture.reenable(),
            FrontendRequest::EnableEmulation => self.emulation.reenable(),
            FrontendRequest::Enumerate() => self.enumerate(),
            FrontendRequest::UpdateFixIps(handle, fix_ips) => {
                self.update_fix_ips(handle, fix_ips);
                self.save_config();
            }
            FrontendRequest::UpdateHostname(handle, host) => {
                self.update_hostname(handle, host);
                self.save_config();
            }
            FrontendRequest::UpdatePort(handle, port) => {
                self.update_port(handle, port);
                self.save_config();
            }
            FrontendRequest::UpdatePosition(handle, pos) => {
                // the old offset was along another edge
                self.arrange(handle, pos, None)
            }
            FrontendRequest::ResolveDns(handle) => self.resolve(handle),
            FrontendRequest::Sync => self.sync_frontend(),
            FrontendRequest::RemoveAuthorizedKey(key) => {
                self.remove_authorized_key(key);
                self.save_config();
            }
            FrontendRequest::UpdateEnterHook(handle, enter_hook) => {
                self.update_enter_hook(handle, enter_hook)
            }
            FrontendRequest::UpdateOffset(handle, offset) => {
                if let Some(pos) = self.client_manager.get_pos(handle) {
                    self.arrange(handle, pos, offset);
                }
            }
            FrontendRequest::Arrange {
                handle,
                pos,
                offset,
            } => self.arrange(handle, pos, offset),
            FrontendRequest::UpdateLeaveHook(handle, leave_hook) => {
                self.update_leave_hook(handle, leave_hook)
            }
            FrontendRequest::SaveConfiguration => self.save_config(),
            FrontendRequest::Discover => self.broadcast_discovered(),
            FrontendRequest::SendFiles {
                id,
                fingerprint,
                paths,
            } => self.send_files(id, fingerprint, paths),
            FrontendRequest::SetClipboard(enabled) => {
                if let Some(control) = &self.control {
                    control.set_clipboard(enabled);
                }
                self.config.set_clipboard(enabled);
                self.save_config();
                self.notify_frontend(FrontendEvent::ClipboardStatus(enabled));
            }
            FrontendRequest::FetchLog { fingerprint } => self.fetch_log(fingerprint),
            FrontendRequest::SetExitShortcut { enabled, keys } => {
                self.set_exit_shortcut(enabled, keys)
            }
            FrontendRequest::Pair { fingerprint, pos } => self.start_pairing(fingerprint, pos),
            FrontendRequest::PairResponse {
                fingerprint,
                accept,
            } => self.answer_pairing(fingerprint, accept),
            FrontendRequest::PairConfirm {
                fingerprint,
                confirm,
            } => self.confirm_pairing(fingerprint, confirm),
        }
    }

    fn save_config(&mut self) {
        let clients = self.client_manager.clients();
        let clients = clients
            .into_iter()
            .map(|(c, s)| ConfigClient {
                ips: HashSet::from_iter(c.fix_ips),
                hostname: c.hostname,
                port: c.port,
                pos: c.pos,
                active: s.active,
                enter_hook: c.cmd,
                leave_hook: c.leave_cmd,
                offset: c.offset,
                fingerprint: c.fingerprint,
                arranged_at: c.arranged_at,
            })
            .collect();
        self.config.set_clients(clients);
        let authorized_keys = self.authorized_keys.read().expect("lock").clone();
        self.config.set_authorized_keys(authorized_keys);
        if let Err(e) = self.config.write_back() {
            log::warn!("failed to write config: {e}");
        }
    }

    fn handle_config_change(&mut self) {
        for h in self.client_manager.registered_clients() {
            self.remove_client(h);
        }
        for c in self.config.clients() {
            let handle = self.client_manager.add_with_config(c);
            log::info!("added client {handle}");
            let (c, s) = self.client_manager.get_state(handle).unwrap();
            if s.active {
                self.client_manager.deactivate_client(handle);
                self.activate_client(handle);
            }
            self.notify_frontend(FrontendEvent::Created(handle, c, s));
        }
        self.capture
            .set_exit_shortcut(self.config.active_exit_shortcut());
        self.notify_exit_shortcut();
        let authorized_keys = self.config.authorized_fingerprints();
        self.authorized_keys
            .write()
            .unwrap()
            .clone_from(&authorized_keys);
        self.sync_frontend();
    }

    async fn handle_frontend_pending(&mut self) {
        let mut pairing_asked = false;
        while let Some(event) = self.pending_frontend_events.pop_front() {
            pairing_asked |= matches!(event, FrontendEvent::PairRequest { .. });
            self.frontend_listener.broadcast(event).await;
        }
        // A pairing request nobody sees would just time out as declined.
        if pairing_asked && !self.frontend_listener.has_frontends() {
            open_frontend();
        }
    }

    fn handle_emulation_event(&mut self, event: EmulationEvent) {
        match event {
            EmulationEvent::ConnectionAttempt { fingerprint } => {
                self.notify_frontend(FrontendEvent::ConnectionAttempt { fingerprint });
            }
            EmulationEvent::Entered {
                addr,
                pos,
                fingerprint,
            } => {
                // check if already registered
                if !self.incoming_conns.contains(&addr) {
                    self.add_incoming(addr, pos, fingerprint.clone());
                    self.notify_frontend(FrontendEvent::DeviceEntered {
                        fingerprint,
                        addr,
                        pos,
                    });
                } else {
                    self.update_incoming(addr, pos, fingerprint);
                }
            }
            EmulationEvent::Disconnected { addr } => {
                if let Some(addr) = self.remove_incoming(addr) {
                    self.notify_frontend(FrontendEvent::IncomingDisconnected(addr));
                }
            }
            EmulationEvent::PortChanged(port) => match port {
                Ok(port) => {
                    self.port = port;
                    // clipboard, pairing and the announcement follow the input port
                    if let Some(control) = &mut self.control {
                        control.rebind(port);
                    }
                    if let Some(discovery) = &mut self.discovery {
                        discovery.set_port(port);
                    }
                    self.notify_frontend(FrontendEvent::PortChanged(port, None));
                }
                Err(e) => self
                    .notify_frontend(FrontendEvent::PortChanged(self.port, Some(format!("{e}")))),
            },
            EmulationEvent::EmulationDisabled => {
                self.emulation_status = Status::Disabled;
                self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
            }
            EmulationEvent::EmulationEnabled => {
                self.emulation_status = Status::Enabled;
                self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
            }
            EmulationEvent::ReleaseNotify => self.capture.release(),
            EmulationEvent::Connected { addr, fingerprint } => {
                self.notify_frontend(FrontendEvent::DeviceConnected { addr, fingerprint });
            }
            EmulationEvent::PeerHello { addr, commit } => {
                // Map the peer's source addr back to its client handle
                // and stamp the commit. Skip if we don't have an
                // outgoing client configured for this peer (incoming-
                // only setup) — there's nowhere to display the version
                // in that case anyway.
                if let Some(handle) = self.client_manager.get_client(addr) {
                    self.client_manager.set_peer_commit(handle, Some(commit));
                    self.broadcast_client(handle);
                }
            }
        }
    }

    fn handle_capture_event(&mut self, event: ICaptureEvent) {
        match event {
            ICaptureEvent::CaptureBegin(handle) => {
                // we entered the capture zone for an incoming connection
                // => notify it that its capture should be released
                if let Some(incoming) = self.incoming_conn_info.get(&handle) {
                    self.emulation.send_leave_event(incoming.addr);
                }
            }
            ICaptureEvent::CaptureDisabled => {
                self.capture_status = Status::Disabled;
                self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
            }
            ICaptureEvent::CaptureEnabled => {
                self.capture_status = Status::Enabled;
                self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
            }
            ICaptureEvent::ClientEntered(handle) => {
                log::info!("entering client {handle} ...");
                self.visit = Some(Visit {
                    handle,
                    released: false,
                    drag: None,
                });
                if let Some(files) = drag::dragged_files() {
                    self.carry_drag(handle, files);
                } else if input_capture::drag_pending() {
                    self.wait_for_dragged_files(handle);
                }
                self.notify_frontend(FrontendEvent::Controlling(Some(handle)));
                self.spawn_hook_command(handle, HookKind::Enter);
                if let (Some(control), Some(addr)) =
                    (&self.control, self.client_manager.active_addr(handle))
                {
                    control.send_clipboard(addr);
                }
            }
            ICaptureEvent::PrimaryReleased(handle) => {
                if let Some(visit) = self.visit.as_mut().filter(|v| v.handle == handle) {
                    visit.released = true;
                    if let Some(drag) = &visit.drag {
                        log::info!("dropped the dragged files on client {handle}");
                        let _ = drag.send(Some(true));
                        // the drag still waits here for the release that
                        // went there: end it now, or it stays on screen
                        drag::cancel_local_drag();
                    }
                }
            }
            ICaptureEvent::ClientLeft(handle) => {
                log::info!("leaving client {handle} ...");
                if let Some(visit) = self.visit.take().filter(|v| v.handle == handle) {
                    // back with the button still held: the drag is taken back
                    // (after a drop there, it was ended when dropped)
                    if let (Some(drag), false) = (visit.drag, visit.released) {
                        let _ = drag.send(Some(false));
                    }
                }
                self.notify_frontend(FrontendEvent::Controlling(None));
                self.spawn_hook_command(handle, HookKind::Leave);
            }
        }
    }

    fn handle_resolver_event(&mut self, event: DnsEvent) {
        let handle = match event {
            DnsEvent::Resolving(handle) => {
                self.client_manager.set_resolving(handle, true);
                handle
            }
            DnsEvent::Resolved(handle, hostname, ips) => {
                self.client_manager.set_resolving(handle, false);
                if let Err(e) = &ips {
                    log::warn!("could not resolve {hostname}: {e}");
                }
                let mut ips = ips.unwrap_or_default();
                // where name lookup fails (no mDNS resolver), fall back to
                // the addresses the device announces itself
                if ips.is_empty() {
                    ips = self.announced_ips(handle).unwrap_or_default();
                }
                self.client_manager.set_dns_ips(handle, ips);
                handle
            }
        };
        self.broadcast_client(handle);
    }

    fn handle_control_event(&mut self, event: ControlEvent) {
        match event {
            ControlEvent::PeerLog {
                fingerprint,
                result,
            } => {
                let name = self.device_name(&fingerprint);
                let saved = result.and_then(|log| {
                    let path = diagnostics::peer_log_path(&name).ok_or("no cache folder")?;
                    std::fs::create_dir_all(path.parent().expect("folder"))
                        .and_then(|()| std::fs::write(&path, log))
                        .map_err(|e| e.to_string())?;
                    Ok(path)
                });
                let (path, error) = match saved {
                    Ok(path) => {
                        log::info!("saved the log of {name} to {}", path.display());
                        (Some(path.display().to_string()), None)
                    }
                    Err(e) => {
                        log::warn!("could not get the log of {name}: {e}");
                        (None, Some(e))
                    }
                };
                self.notify_frontend(FrontendEvent::PeerLog {
                    fingerprint,
                    path,
                    error,
                });
            }
            ControlEvent::Updated { version } => {
                log::info!("restarting to run the update {version}");
                update::restart_app();
                // macOS starts the service again, from the new app
                tokio::task::spawn_local(async {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    std::process::exit(0);
                });
            }
            ControlEvent::UpdateSent {
                fingerprint,
                version,
                result,
            } => {
                let name = self.device_name(&fingerprint);
                match result {
                    Ok(()) => log::info!("sent the update {version} to {name}"),
                    Err(e) => log::warn!("{name} did not take the update {version}: {e}"),
                }
            }
            ControlEvent::Request {
                fingerprint,
                request,
                code,
                reply,
            } => {
                // Requests that timed out (the control channel gave up waiting
                // and dropped its end) no longer count.
                self.pending_pairs.retain(|_, p| !p.reply.is_closed());
                // Anyone on the network can ask; don't let them bury the user
                // in dialogs. Dropping `reply` declines the request.
                if self.pending_pairs.len() >= MAX_PENDING_PAIRS
                    && !self.pending_pairs.contains_key(&fingerprint)
                {
                    log::warn!(
                        "declined pairing request from {}: too many pending",
                        request.name
                    );
                    return;
                }
                self.notify_frontend(FrontendEvent::PairRequest {
                    fingerprint: fingerprint.clone(),
                    name: request.name.clone(),
                    code: code.clone(),
                    pos: request.pos,
                });
                // a newer request from the same device replaces (declines) the old one
                self.pending_pairs.insert(
                    fingerprint,
                    PendingPair {
                        request,
                        code,
                        reply,
                    },
                );
            }
            ControlEvent::Confirmed {
                fingerprint,
                request,
                confirmed,
            } => {
                let status = if confirmed {
                    self.complete_pairing(
                        &fingerprint,
                        &request.name,
                        &request.hostname,
                        request.port,
                        request.pos,
                    );
                    PairStatus::Paired
                } else {
                    PairStatus::Declined
                };
                self.notify_frontend(FrontendEvent::PairUpdate {
                    fingerprint,
                    name: request.name,
                    status,
                });
            }
            ControlEvent::Code { fingerprint, code } => {
                let name = display_name(
                    self.discovery
                        .as_ref()
                        .and_then(|d| d.get(&fingerprint))
                        .as_ref(),
                );
                self.notify_frontend(FrontendEvent::PairUpdate {
                    fingerprint,
                    name,
                    status: PairStatus::Waiting { code },
                });
            }
            ControlEvent::Layout {
                fingerprint,
                layout,
            } => self.apply_layout(&fingerprint, layout),
            ControlEvent::Transfer(mut update) => {
                update.name = self.device_name(&update.fingerprint);
                // Files dragged from here were dropped over there: a drag
                // carried by the other device's mouse still waits here for
                // its button release (emulated here, but the release
                // happened over there). Let go of it, on the edge strip.
                let dropped_there = !update.incoming
                    && update.dragged
                    && matches!(update.state, TransferState::Done { .. });
                if dropped_there && cfg!(not(target_os = "macos")) {
                    self.emulation.release_primary();
                }
                self.notify_frontend(FrontendEvent::Transfer(update));
            }
            ControlEvent::Finished {
                fingerprint,
                pos,
                result,
            } => {
                self.outgoing_pairs.remove(&fingerprint);
                let known = self.discovery.as_ref().and_then(|d| d.get(&fingerprint));
                let (name, status) = match result {
                    Ok(reply) if reply.accepted => {
                        // prefer the address the device is announced under
                        let (hostname, port) = known
                            .as_ref()
                            .map(|p| (p.hostname.clone(), p.port))
                            .unwrap_or((reply.hostname, reply.port));
                        self.complete_pairing(&fingerprint, &reply.name, &hostname, port, pos);
                        (reply.name, PairStatus::Paired)
                    }
                    Ok(_) => (display_name(known.as_ref()), PairStatus::Declined),
                    Err(e) => {
                        log::warn!("pairing with {fingerprint} failed: {e}");
                        (
                            display_name(known.as_ref()),
                            PairStatus::Failed(e.to_string()),
                        )
                    }
                };
                log::info!("pairing with {name}: {status:?}");
                self.notify_frontend(FrontendEvent::PairUpdate {
                    fingerprint,
                    name,
                    status,
                });
            }
        }
    }

    /// Addresses the device behind client `handle` announces on the network.
    fn announced_ips(&self, handle: ClientHandle) -> Option<Vec<IpAddr>> {
        let (config, _) = self.client_manager.get_state(handle)?;
        let hostname = config.hostname?;
        self.discovery
            .as_ref()?
            .peers(|_| false)
            .into_iter()
            .find(|p| p.port == config.port && same_host(&p.hostname, &hostname))
            .map(|p| p.ips)
            .filter(|ips| !ips.is_empty())
    }

    /// Discovery follows devices as their addresses change (new network,
    /// new DHCP lease): hand the new addresses to their clients right away.
    fn update_announced_ips(&mut self) {
        for (handle, _, state) in self.client_manager.get_client_states() {
            let Some(ips) = self.announced_ips(handle) else {
                continue;
            };
            if ips.iter().any(|ip| !state.ips.contains(ip)) {
                log::info!("client {handle} is now announced at {ips:?}");
                self.client_manager.set_dns_ips(handle, ips);
                self.broadcast_client(handle);
            }
        }
    }

    fn broadcast_discovered(&mut self) {
        let Some(discovery) = &self.discovery else {
            self.notify_frontend(FrontendEvent::Discovered(vec![]));
            return;
        };
        let keys = self.authorized_keys.read().expect("lock").clone();
        let peers = discovery.peers(|fp| keys.contains_key(fp));
        self.notify_frontend(FrontendEvent::Discovered(peers));
    }

    /// Ask the discovered device `fingerprint` to pair; it will sit at `pos`.
    fn start_pairing(&mut self, fingerprint: String, pos: Position) {
        let peer = self.discovery.as_ref().and_then(|d| d.get(&fingerprint));
        let (Some(control), Some(peer)) = (&self.control, peer) else {
            let status = PairStatus::Failed("device not found on the network".to_owned());
            self.notify_frontend(FrontendEvent::PairUpdate {
                name: fingerprint.clone(),
                fingerprint,
                status,
            });
            return;
        };
        let Some(&ip) = peer.ips.first() else {
            let status = PairStatus::Failed("device has no reachable address".to_owned());
            self.notify_frontend(FrontendEvent::PairUpdate {
                fingerprint,
                name: peer.name,
                status,
            });
            return;
        };
        // one pairing per device at a time: a second click would start
        // another exchange with a different code
        if self.outgoing_pairs.contains_key(&fingerprint) {
            log::info!("already pairing with {}", peer.name);
            return;
        }
        let request = PairRequest {
            name: self.name.clone(),
            hostname: self.hostname.clone(),
            port: self.port,
            pos: pos.opposite(),
        };
        log::info!("asking {} to pair", peer.name);
        // the code is known once both sides exchanged their contributions
        // (ControlEvent::Code); the user then confirms it (confirm_pairing)
        let (confirm_tx, confirm_rx) = oneshot::channel();
        self.outgoing_pairs.insert(fingerprint.clone(), confirm_tx);
        control.pair(
            SocketAddr::new(ip, peer.port),
            fingerprint,
            pos,
            request,
            confirm_rx,
        );
    }

    /// The user compared the code of a pairing this device started.
    fn confirm_pairing(&mut self, fingerprint: String, confirm: bool) {
        match self.outgoing_pairs.remove(&fingerprint) {
            Some(tx) => {
                let _ = tx.send(confirm);
            }
            None => log::warn!("no pairing with {fingerprint} to confirm"),
        }
    }

    fn answer_pairing(&mut self, fingerprint: String, accept: bool) {
        let Some(PendingPair {
            request,
            code,
            reply,
        }) = self.pending_pairs.remove(&fingerprint)
        else {
            log::warn!("no pending pairing request from {fingerprint}");
            return;
        };
        let answer = PairReply {
            accepted: accept,
            name: self.name.clone(),
            hostname: self.hostname.clone(),
            port: self.port,
        };
        if reply.send(answer).is_err() {
            let status = PairStatus::Failed("the request expired".to_owned());
            self.notify_frontend(FrontendEvent::PairUpdate {
                fingerprint,
                name: request.name,
                status,
            });
            return;
        }
        // Accepting isn't enough: the other device's user confirms the code
        // too, and only then is it trusted (ControlEvent::Confirmed).
        let status = if accept {
            PairStatus::Waiting { code }
        } else {
            PairStatus::Declined
        };
        self.notify_frontend(FrontendEvent::PairUpdate {
            fingerprint,
            name: request.name,
            status,
        });
    }

    /// Trust the paired device and set up a client for it at `pos`,
    /// reusing an existing client with the same address.
    fn complete_pairing(
        &mut self,
        fingerprint: &str,
        name: &str,
        hostname: &str,
        port: u16,
        pos: Position,
    ) {
        self.add_authorized_key(name.to_owned(), fingerprint.to_owned());
        let existing = self
            .client_manager
            .get_client_states()
            .into_iter()
            .find(|(_, c, _)| {
                c.port == port
                    && c.hostname
                        .as_deref()
                        .is_some_and(|h| same_host(h, hostname))
            })
            .map(|(handle, _, _)| handle);
        let handle = match existing {
            Some(handle) => handle,
            None => {
                let handle = self.client_manager.add_client();
                let (c, s) = self.client_manager.get_state(handle).expect("new client");
                self.notify_frontend(FrontendEvent::Created(handle, c, s));
                self.update_hostname(handle, Some(hostname.to_owned()));
                self.update_port(handle, port);
                handle
            }
        };
        self.client_manager
            .set_fingerprint(handle, Some(fingerprint.to_owned()));
        self.update_pos(handle, pos);
        self.client_manager.set_offset(handle, None, now_millis());
        self.activate_client(handle);
        self.save_config();
        log::info!("paired with {name} ({hostname}), placed {pos}");
    }

    /// Send files to the paired device with `fingerprint`: to where it is
    /// announced on the network, or else where it is connected.
    fn send_files(&mut self, id: u64, fingerprint: String, paths: Vec<std::path::PathBuf>) {
        let addr = self.destination(&fingerprint);
        let paired = self
            .authorized_keys
            .read()
            .expect("lock")
            .contains_key(&fingerprint);
        let problem = match (&self.control, &addr) {
            _ if !paired => Some("that device isn't paired"),
            (None, _) => Some("file transfer is unavailable"),
            (_, None) => Some("the device isn't on the network"),
            _ => None,
        };
        if let Some(problem) = problem {
            let name = self.device_name(&fingerprint);
            self.notify_frontend(FrontendEvent::Transfer(TransferUpdate {
                id,
                fingerprint,
                name,
                incoming: false,
                dragged: false,
                files: 0,
                done: 0,
                total: 0,
                state: TransferState::Failed(problem.to_owned()),
            }));
            return;
        }
        let (Some(control), Some(addr)) = (&self.control, addr) else {
            return;
        };
        log::info!("sending {} items to {addr}", paths.len());
        control.send_files(id, addr, fingerprint, paths, None, false);
    }

    /// A drag crossed to client `handle` while its files were still being
    /// read from its source (a quick crossing): carry it once they are
    /// known, if that is soon.
    fn wait_for_dragged_files(&self, handle: ClientHandle) {
        let found = self.late_drag_tx.clone();
        tokio::task::spawn_local(async move {
            for _ in 0..8 {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if let Some(files) = input_capture::current_drag() {
                    let _ = found.send((handle, files));
                    return;
                }
                if !input_capture::drag_pending() {
                    return;
                }
            }
            log::info!("the dragged files didn't arrive in time");
        });
    }

    /// Start sending the files of a drag that just crossed to client
    /// `handle`; they are kept there only if it ends in a drop there.
    fn carry_drag(&mut self, handle: ClientHandle, files: Vec<std::path::PathBuf>) {
        let Some(fingerprint) = self.client_fingerprint(handle) else {
            log::info!("not carrying the drag: client {handle} isn't paired");
            return;
        };
        let Some(addr) = self.client_manager.active_addr(handle) else {
            return;
        };
        let (Some(control), Some(visit)) = (&self.control, self.visit.as_mut()) else {
            return;
        };
        let (outcome, drag) = tokio::sync::watch::channel(None);
        visit.drag = Some(outcome);
        let id = now_millis() ^ (files.len() as u64).rotate_left(48);
        log::info!(
            "carrying a drag of {} items to client {handle}",
            files.len()
        );
        // on this platform, can the drag end on the receiver with its own
        // mouse? (Linux: yes, when that mouse controls this device)
        let release_drops = cfg!(not(target_os = "macos"));
        control.send_files(
            id,
            Destination::Addr(addr),
            fingerprint,
            files,
            Some(drag),
            release_drops,
        );
    }

    /// Where to reach the device with `fingerprint` on the control channel:
    /// where it is announced on the network, or else where it is connected,
    /// or else its host name.
    fn destination(&self, fingerprint: &str) -> Option<Destination> {
        let announced = self
            .discovery
            .as_ref()
            .and_then(|d| d.get(fingerprint))
            .and_then(|p| p.ips.first().map(|&ip| SocketAddr::new(ip, p.port)));
        let client = self.client_manager.find_by_fingerprint(fingerprint);
        let connected = || self.client_manager.active_addr(client?);
        // last resort, as for input: its host name (e.g. after a network
        // change, before it is announced again)
        let by_name = || {
            let (config, _) = self.client_manager.get_state(client?)?;
            Some(Destination::Host(config.hostname?, config.port))
        };
        announced
            .or_else(connected)
            .map(Destination::Addr)
            .or_else(by_name)
    }

    /// Ask a paired device for its log, saved for a problem report.
    fn fetch_log(&mut self, fingerprint: String) {
        let problem = match (&self.control, self.destination(&fingerprint)) {
            (None, _) => "the control channel is unavailable".to_owned(),
            (_, None) => "the device isn't on the network".to_owned(),
            (Some(control), Some(destination)) => {
                control.fetch_log(destination, fingerprint);
                return;
            }
        };
        self.notify_frontend(FrontendEvent::PeerLog {
            fingerprint,
            path: None,
            error: Some(problem),
        });
    }

    /// What the user calls the device with `fingerprint`.
    fn device_name(&self, fingerprint: &str) -> String {
        if let Some(peer) = self.discovery.as_ref().and_then(|d| d.get(fingerprint)) {
            return peer.name;
        }
        self.authorized_keys
            .read()
            .expect("lock")
            .get(fingerprint)
            .cloned()
            .unwrap_or_else(|| fingerprint.chars().take(11).collect())
    }

    /// Connections made by pairing whose device is no longer trusted (left
    /// over from forgetting it before that removed both): useless, and they
    /// hide the device from pairing again.
    fn forget_untrusted_clients(&mut self) {
        let untrusted: Vec<_> = {
            let keys = self.authorized_keys.read().expect("lock");
            self.client_manager
                .get_client_states()
                .into_iter()
                .filter(|(_, c, _)| {
                    c.fingerprint
                        .as_ref()
                        .is_some_and(|fp| !keys.contains_key(fp))
                })
                .map(|(handle, _, _)| handle)
                .collect()
        };
        for &handle in &untrusted {
            log::info!("forgetting client {handle}: its device is no longer trusted");
            self.remove_client(handle);
        }
        if !untrusted.is_empty() {
            self.save_config();
        }
    }

    /// Place client `handle` at `pos` with `offset` (see
    /// [`lan_mouse_ipc::ClientConfig::offset`]), and tell the other device,
    /// which keeps the same arrangement from its side.
    fn arrange(&mut self, handle: ClientHandle, pos: Position, offset: Option<i32>) {
        self.update_pos(handle, pos);
        self.client_manager.set_offset(handle, offset, now_millis());
        self.broadcast_client(handle);
        self.save_config();
        self.send_layout(handle);
    }

    /// The other device's layout: take its monitors, and its arrangement if
    /// it is newer than ours. If ours is newer, it gets ours.
    fn apply_layout(&mut self, fingerprint: &str, layout: Layout) {
        let Some(handle) = self.client_for_fingerprint(fingerprint) else {
            log::info!("got a screen arrangement from {fingerprint}, which has no connection here");
            return;
        };
        self.client_manager
            .set_peer_monitors(handle, layout.monitors.clone());
        let Some((config, _)) = self.client_manager.get_state(handle) else {
            return;
        };
        let same = layout.pos == config.pos && layout.offset == config.offset;
        match arrangement_decision(
            config.arranged_at.unwrap_or(0),
            layout.arranged_at,
            same,
            fingerprint > self.public_key_fingerprint.as_str(),
        ) {
            ArrangementDecision::Take => {
                log::info!(
                    "the other device rearranged the screens: it is {}, offset {:?}",
                    layout.pos,
                    layout.offset
                );
                self.update_pos(handle, layout.pos);
                self.client_manager
                    .set_offset(handle, layout.offset, layout.arranged_at);
                self.save_config();
            }
            ArrangementDecision::Keep => {}
            ArrangementDecision::Send => self.send_layout(handle),
        }
        self.broadcast_client(handle);
    }

    /// Send our monitors and arrangement to the device behind `handle`, if
    /// it is connected.
    fn send_layout(&mut self, handle: ClientHandle) {
        let Some(addr) = self.client_manager.active_addr(handle) else {
            return;
        };
        let Some(fingerprint) = self.client_fingerprint(handle) else {
            log::debug!("client {handle} isn't paired: can't share the arrangement");
            return;
        };
        let (Some(control), Some((config, _))) =
            (&self.control, self.client_manager.get_state(handle))
        else {
            return;
        };
        let layout = Layout {
            monitors: self.monitors.clone(),
            pos: config.pos.opposite(),
            offset: config.offset.map(|o| -o),
            arranged_at: config.arranged_at.unwrap_or(0),
        };
        control.send_layout(addr, fingerprint, layout);
        self.layout_sent.insert(handle, addr);
    }

    /// A client that just connected (at a new address) gets our layout.
    fn share_layout_on_connect(&mut self, handle: ClientHandle) {
        let connected = self
            .client_manager
            .get_state(handle)
            .filter(|(_, s)| s.alive)
            .and_then(|(_, s)| s.active_addr);
        match connected {
            Some(addr) if self.layout_sent.get(&handle) != Some(&addr) => self.send_layout(handle),
            Some(_) => {}
            None => {
                self.layout_sent.remove(&handle);
            }
        }
    }

    /// Send a connected Mac the newest build for it, if it runs another
    /// version: Macs are updated from here instead of by hand. Offered once
    /// per version and device every [`UPDATE_RETRY`].
    fn offer_update(&mut self, handle: ClientHandle) {
        let Some(fingerprint) = self.client_fingerprint(handle) else {
            return;
        };
        let Some(peer) = self.discovery.as_ref().and_then(|d| d.get(&fingerprint)) else {
            return;
        };
        if peer.os != "macos" {
            return;
        }
        let Some((zip, version)) = update::mac_build(&peer.arch) else {
            return;
        };
        // its version, once it said (right after connecting)
        let Some(running) = self
            .client_manager
            .get_state(handle)
            .and_then(|(_, s)| s.peer_commit)
            .map(|c| String::from_utf8_lossy(&c).into_owned())
        else {
            return;
        };
        if version.starts_with(&running) || running.starts_with(&version) {
            return;
        }
        if let Some((offered, at)) = self.update_offers.get(&fingerprint) {
            if *offered == version && at.elapsed() < UPDATE_RETRY {
                return;
            }
        }
        let (Some(control), Some(&ip)) = (&self.control, peer.ips.first()) else {
            return;
        };
        log::info!(
            "sending {} the update {version} (it runs {running})",
            peer.name
        );
        self.update_offers.insert(
            fingerprint.clone(),
            (version.clone(), std::time::Instant::now()),
        );
        control.send_update(
            Destination::Addr(SocketAddr::new(ip, peer.port)),
            fingerprint,
            zip,
            version,
        );
    }

    /// Tell connected devices when our monitors changed.
    fn check_monitors(&mut self) {
        if self.layout_sent.is_empty() {
            return;
        }
        let monitors = local_monitors();
        if monitors.is_empty() || monitors == self.monitors {
            return;
        }
        log::info!("the monitors changed");
        self.monitors = monitors;
        let handles: Vec<_> = self.layout_sent.keys().copied().collect();
        for handle in handles {
            self.send_layout(handle);
        }
    }

    /// The certificate fingerprint of the device behind client `handle`:
    /// recorded when pairing, or found through discovery for clients set up
    /// before that (and recorded then).
    fn client_fingerprint(&mut self, handle: ClientHandle) -> Option<String> {
        let (config, _) = self.client_manager.get_state(handle)?;
        if config.fingerprint.is_some() {
            return config.fingerprint;
        }
        let hostname = config.hostname?;
        let fingerprint = self
            .discovery
            .as_ref()?
            .peers(|_| false)
            .into_iter()
            .find(|p| p.port == config.port && same_host(&p.hostname, &hostname))?
            .fingerprint;
        if !self
            .authorized_keys
            .read()
            .expect("lock")
            .contains_key(&fingerprint)
        {
            return None;
        }
        self.client_manager
            .set_fingerprint(handle, Some(fingerprint.clone()));
        self.save_config();
        Some(fingerprint)
    }

    /// The client for the paired device with `fingerprint`.
    fn client_for_fingerprint(&mut self, fingerprint: &str) -> Option<ClientHandle> {
        if let Some(handle) = self.client_manager.find_by_fingerprint(fingerprint) {
            return Some(handle);
        }
        // a client set up before fingerprints were recorded
        let handles: Vec<_> = self
            .client_manager
            .get_client_states()
            .into_iter()
            .filter(|(_, c, _)| c.fingerprint.is_none())
            .map(|(handle, _, _)| handle)
            .collect();
        handles
            .into_iter()
            .find(|&handle| self.client_fingerprint(handle).as_deref() == Some(fingerprint))
    }

    /// Looks up the addresses of clients that aren't connected again, about
    /// once a minute: they may have moved to another address (restarted,
    /// another network) without announcing it.
    fn resolve_unconnected(&self) {
        for handle in self.client_manager.active_clients() {
            if self.client_manager.active_addr(handle).is_none() {
                self.resolve(handle);
            }
        }
    }

    /// Switch the exit shortcut on or off, and change its keys (`None`:
    /// keep them).
    fn set_exit_shortcut(&mut self, enabled: bool, keys: Option<String>) {
        let shortcut = match keys.as_deref().map(str::parse::<Shortcut>) {
            None => self.config.exit_shortcut(),
            Some(Ok(shortcut)) => shortcut,
            Some(Err(e)) => {
                return self.notify_frontend(FrontendEvent::Error(format!(
                    "can't use that exit shortcut: {e}"
                )));
            }
        };
        self.config.set_exit_shortcut(enabled, &shortcut);
        self.save_config();
        self.capture
            .set_exit_shortcut(self.config.active_exit_shortcut());
        self.notify_exit_shortcut();
    }

    fn notify_exit_shortcut(&mut self) {
        self.notify_frontend(FrontendEvent::ExitShortcut {
            enabled: self.config.exit_shortcut_enabled(),
            keys: self.config.exit_shortcut().to_string(),
        });
    }

    fn resolve(&self, handle: ClientHandle) {
        if let Some(hostname) = self.client_manager.get_hostname(handle) {
            self.resolver.resolve(handle, hostname);
        }
    }

    fn sync_frontend(&mut self) {
        self.enumerate();
        self.notify_frontend(FrontendEvent::EmulationStatus(self.emulation_status));
        self.notify_frontend(FrontendEvent::CaptureStatus(self.capture_status));
        self.notify_frontend(FrontendEvent::PortChanged(self.port, None));
        self.notify_frontend(FrontendEvent::PublicKeyFingerprint(
            self.public_key_fingerprint.clone(),
        ));
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
        self.notify_frontend(FrontendEvent::ClipboardStatus(self.config.clipboard()));
        self.notify_exit_shortcut();
        // requests that arrived before this frontend connected
        self.pending_pairs.retain(|_, p| !p.reply.is_closed());
        let requests: Vec<_> = self
            .pending_pairs
            .iter()
            .map(|(fingerprint, p)| FrontendEvent::PairRequest {
                fingerprint: fingerprint.clone(),
                name: p.request.name.clone(),
                code: p.code.clone(),
                pos: p.request.pos,
            })
            .collect();
        for request in requests {
            self.notify_frontend(request);
        }
    }

    const ENTER_HANDLE_BEGIN: u64 = u64::MAX / 2 + 1;

    fn add_incoming(&mut self, addr: SocketAddr, pos: Position, fingerprint: String) {
        let handle = Self::ENTER_HANDLE_BEGIN + self.next_trigger_handle;
        self.next_trigger_handle += 1;
        self.capture.create(handle, pos, CaptureType::EnterOnly);
        self.incoming_conns.insert(addr);
        self.incoming_conn_info.insert(
            handle,
            Incoming {
                fingerprint,
                addr,
                pos,
            },
        );
    }

    fn update_incoming(&mut self, addr: SocketAddr, pos: Position, fingerprint: String) {
        let incoming = self
            .incoming_conn_info
            .iter_mut()
            .find(|(_, i)| i.addr == addr)
            .map(|(_, i)| i)
            .expect("no such client");
        let mut changed = false;
        if incoming.fingerprint != fingerprint {
            incoming.fingerprint = fingerprint.clone();
            changed = true;
        }
        if incoming.pos != pos {
            incoming.pos = pos;
            changed = true;
        }
        if changed {
            self.remove_incoming(addr);
            self.add_incoming(addr, pos, fingerprint.clone());
            self.notify_frontend(FrontendEvent::IncomingDisconnected(addr));
            self.notify_frontend(FrontendEvent::DeviceEntered {
                fingerprint,
                addr,
                pos,
            });
        }
    }

    fn remove_incoming(&mut self, addr: SocketAddr) -> Option<SocketAddr> {
        let handle = self
            .incoming_conn_info
            .iter()
            .find(|(_, incoming)| incoming.addr == addr)
            .map(|(k, _)| *k)?;
        self.capture.destroy(handle);
        self.incoming_conns.remove(&addr);
        self.incoming_conn_info
            .remove(&handle)
            .map(|incoming| incoming.addr)
    }

    fn notify_frontend(&mut self, event: FrontendEvent) {
        self.pending_frontend_events.push_back(event);
        self.frontend_event_pending.notify_one();
    }

    fn add_authorized_key(&mut self, desc: String, fp: String) {
        self.authorized_keys.write().expect("lock").insert(fp, desc);
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
        // discovered devices carry a `paired` flag derived from these keys
        self.broadcast_discovered();
    }

    fn remove_authorized_key(&mut self, fp: String) {
        // A connection to a device no longer trusted is of no use, and it
        // would keep the device listed as paired (and not offered for
        // pairing again): forget the device entirely. Found while it is
        // still trusted (older connections are matched through discovery,
        // for trusted devices only).
        let handles: Vec<_> = self
            .client_manager
            .get_client_states()
            .into_iter()
            .map(|(handle, _, _)| handle)
            .collect();
        let forget: Vec<_> = handles
            .into_iter()
            .filter(|&handle| self.client_fingerprint(handle).as_deref() == Some(fp.as_str()))
            .collect();
        self.authorized_keys.write().expect("lock").remove(&fp);
        self.emulation.disconnect(fp.clone());
        for &handle in &forget {
            log::info!("forgetting client {handle}: its device is no longer trusted");
            self.remove_client(handle);
        }
        if !forget.is_empty() {
            self.save_config();
        }
        let keys = self.authorized_keys.read().expect("lock").clone();
        self.notify_frontend(FrontendEvent::AuthorizedUpdated(keys));
        self.broadcast_discovered();
    }

    fn enumerate(&mut self) {
        let clients = self.client_manager.get_client_states();
        self.notify_frontend(FrontendEvent::Enumerate(clients));
    }

    fn add_client(&mut self) {
        let handle = self.client_manager.add_client();
        log::info!("added client {handle}");
        let (c, s) = self.client_manager.get_state(handle).unwrap();
        self.notify_frontend(FrontendEvent::Created(handle, c, s));
    }

    fn set_client_active(&mut self, handle: ClientHandle, active: bool) {
        if active {
            self.activate_client(handle);
        } else {
            self.deactivate_client(handle);
        }
    }

    fn deactivate_client(&mut self, handle: ClientHandle) {
        log::debug!("deactivating client {handle}");
        if self.client_manager.deactivate_client(handle) {
            self.capture.destroy(handle);
            self.broadcast_client(handle);
            log::info!("deactivated client {handle}");
            self.watch_drag_edges();
        }
    }

    /// Watch the edges that lead to other devices for files dragged there
    /// (Wayland shows a drag only to the surface under the pointer).
    fn watch_drag_edges(&self) {
        let edges = self
            .client_manager
            .active_clients()
            .into_iter()
            .filter_map(|handle| self.client_manager.get_pos(handle))
            .map(|pos| match pos {
                Position::Left => input_capture::Position::Left,
                Position::Right => input_capture::Position::Right,
                Position::Top => input_capture::Position::Top,
                Position::Bottom => input_capture::Position::Bottom,
            })
            .collect();
        input_capture::watch_drag_edges(edges);
    }

    fn activate_client(&mut self, handle: ClientHandle) {
        log::debug!("activating client {handle}");

        /* resolve dns on activate */
        self.resolve(handle);

        /* deactivate potential other client at this position */
        let Some(pos) = self.client_manager.get_pos(handle) else {
            return;
        };

        if let Some(other) = self.client_manager.client_at(pos) {
            if other != handle {
                self.deactivate_client(other);
            }
        }

        /* activate the client */
        if self.client_manager.activate_client(handle) {
            /* notify capture and frontends */
            self.capture.create(handle, pos, CaptureType::Default);
            self.broadcast_client(handle);
            log::info!("activated client {handle} ({pos})");
            self.watch_drag_edges();
        }
    }

    fn change_port(&mut self, port: u16) {
        if self.port != port {
            self.emulation.request_port_change(port);
        } else {
            self.notify_frontend(FrontendEvent::PortChanged(self.port, None));
        }
    }

    fn remove_client(&mut self, handle: ClientHandle) {
        if self
            .client_manager
            .remove_client(handle)
            .map(|(_, s)| s.active)
            .unwrap_or(false)
        {
            self.capture.destroy(handle);
            self.watch_drag_edges();
        }
        self.notify_frontend(FrontendEvent::Deleted(handle));
    }

    fn update_fix_ips(&mut self, handle: ClientHandle, fix_ips: Vec<IpAddr>) {
        self.client_manager.set_fix_ips(handle, fix_ips);
        self.broadcast_client(handle);
    }

    fn update_hostname(&mut self, handle: ClientHandle, hostname: Option<String>) {
        log::info!("hostname changed: {hostname:?}");
        if self.client_manager.set_hostname(handle, hostname.clone()) {
            self.resolve(handle);
        }
        self.broadcast_client(handle);
    }

    fn update_port(&mut self, handle: ClientHandle, port: u16) {
        self.client_manager.set_port(handle, port);
        self.broadcast_client(handle);
    }

    fn update_pos(&mut self, handle: ClientHandle, pos: Position) {
        // update state in event input emulator & input capture
        if self.client_manager.set_pos(handle, pos) {
            self.deactivate_client(handle);
            self.activate_client(handle);
        }
        self.broadcast_client(handle);
    }

    fn update_enter_hook(&mut self, handle: ClientHandle, enter_hook: Option<String>) {
        self.client_manager.set_enter_hook(handle, enter_hook);
        self.broadcast_client(handle);
    }

    fn update_leave_hook(&mut self, handle: ClientHandle, leave_hook: Option<String>) {
        self.client_manager.set_leave_hook(handle, leave_hook);
        self.broadcast_client(handle);
    }

    fn broadcast_client(&mut self, handle: ClientHandle) {
        let event = self
            .client_manager
            .get_state(handle)
            .map(|(c, s)| FrontendEvent::State(handle, c, s))
            .unwrap_or(FrontendEvent::NoSuchClient(handle));
        self.notify_frontend(event);
    }

    fn spawn_hook_command(&self, handle: ClientHandle, kind: HookKind) {
        let cmd = match kind {
            HookKind::Enter => self.client_manager.get_enter_cmd(handle),
            HookKind::Leave => self.client_manager.get_leave_cmd(handle),
        };
        let Some(cmd) = cmd else { return };
        tokio::task::spawn_local(async move {
            log::info!("spawning {kind} hook for client {handle}");
            let mut child = match Command::new("sh").arg("-c").arg(cmd.as_str()).spawn() {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("could not execute {kind} hook for client {handle}: {e}");
                    return;
                }
            };
            match child.wait().await {
                Ok(s) => {
                    if s.success() {
                        log::info!("{kind} hook for client {handle} ({cmd}) exited successfully");
                    } else {
                        log::warn!("{kind} hook for client {handle} ({cmd}) exited with {s}");
                    }
                }
                Err(e) => log::warn!("{kind} hook for client {handle} ({cmd}): {e}"),
            }
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum HookKind {
    Enter,
    Leave,
}

impl std::fmt::Display for HookKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookKind::Enter => f.write_str("enter"),
            HookKind::Leave => f.write_str("leave"),
        }
    }
}

async fn next_control_event(control: &mut Option<Control>) -> ControlEvent {
    match control {
        Some(control) => control.event().await,
        None => std::future::pending().await,
    }
}

async fn discovery_changed(discovery: &mut Option<Discovery>) {
    match discovery {
        Some(discovery) => discovery.changed().await,
        None => std::future::pending().await,
    }
}

fn display_name(peer: Option<&lan_mouse_ipc::DiscoveredPeer>) -> String {
    peer.map(|p| p.name.clone())
        .unwrap_or_else(|| "device".to_owned())
}

/// Host names are case-insensitive, and `.local` names may carry a trailing dot.
fn same_host(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// Start the app that shows pairing requests, when none is connected: on
/// macOS the menu bar app (the service may run without it). Elsewhere the
/// desktop's own frontend (e.g. a bar widget) is expected to be running.
fn open_frontend() {
    #[cfg(target_os = "macos")]
    {
        // <bundle>/Contents/MacOS/lan-mouse
        let bundle = std::env::current_exe().ok().and_then(|exe| {
            let bundle = exe.parent()?.parent()?.parent()?.to_owned();
            bundle
                .extension()
                .is_some_and(|e| e == "app")
                .then_some(bundle)
        });
        let Some(bundle) = bundle else {
            log::warn!("a pairing request is waiting, but no app is open to show it");
            return;
        };
        log::info!("opening Lan Mouse to show a pairing request");
        let opened = std::process::Command::new("/usr/bin/open")
            .args(["-g", "--env", "LAN_MOUSE_HIDDEN=1"])
            .args(["--env", "LAN_MOUSE_SERVICE_MANAGED=1"])
            .arg(bundle)
            .spawn();
        if let Err(e) = opened {
            log::warn!("could not open Lan Mouse: {e}");
        }
    }
    #[cfg(not(target_os = "macos"))]
    log::warn!("a pairing request is waiting, but no app is open to show it");
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// This device's monitors, in logical pixels.
fn local_monitors() -> Vec<Monitor> {
    input_capture::displays()
        .unwrap_or_default()
        .into_iter()
        .map(|d| Monitor {
            x: d.x,
            y: d.y,
            width: d.width,
            height: d.height,
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum ArrangementDecision {
    /// take the other device's arrangement
    Take,
    /// both have the same one already
    Keep,
    /// ours is the one to keep: send it
    Send,
}

/// Which of two arrangements of the same pair of devices wins: the newer
/// one; between equally old but different ones (e.g. both from before
/// arrangements were shared), the one of the device with the greater
/// fingerprint, so both devices decide the same way.
fn arrangement_decision(
    ours_at: u64,
    theirs_at: u64,
    same: bool,
    their_fingerprint_is_greater: bool,
) -> ArrangementDecision {
    if same {
        ArrangementDecision::Keep
    } else if theirs_at > ours_at || (theirs_at == ours_at && their_fingerprint_is_greater) {
        ArrangementDecision::Take
    } else {
        ArrangementDecision::Send
    }
}

/// Waits until this process is asked to stop, and says how.
async fn termination() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut int), Ok(mut term), Ok(mut hup)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            let _ = signal::ctrl_c().await;
            return "interrupted";
        };
        tokio::select! {
            _ = int.recv() => "interrupted (SIGINT: Ctrl+C, or the app that started it quit)",
            _ = term.recv() => "terminated (SIGTERM: e.g. the system stopping it, or logout)",
            _ = hup.recv() => "hung up (SIGHUP: its terminal or session closed)",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
        "interrupted"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_newer_arrangement_wins_on_both_sides() {
        use ArrangementDecision::*;
        // a arranged at 5, b at 3: a sends, b takes
        assert_eq!(arrangement_decision(5, 3, false, false), Send);
        assert_eq!(arrangement_decision(3, 5, false, true), Take);
        // equally old: exactly one of the two takes the other's
        assert_eq!(arrangement_decision(0, 0, false, true), Take);
        assert_eq!(arrangement_decision(0, 0, false, false), Send);
        assert_eq!(arrangement_decision(0, 7, true, false), Keep);
    }
}
