use crate::{
    capture::{Capture, CaptureType, ICaptureEvent},
    client::ClientManager,
    config::{Config, ConfigClient},
    connect::LanMouseConnection,
    control::{Control, PairReply, PairRequest, PairingEvent},
    crypto,
    discovery::{self, Discovery},
    dns::{DnsEvent, DnsResolver},
    emulation::{Emulation, EmulationEvent},
    listen::{LanMouseListener, ListenerCreationError},
};
use futures::StreamExt;
use lan_mouse_ipc::{
    AsyncFrontendListener, ClientHandle, FrontendEvent, FrontendRequest, IpcError,
    IpcListenerCreationError, PairStatus, Position, Status,
};
use log;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
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
}

/// Pairing requests waiting for an answer at the same time; more are declined.
const MAX_PENDING_PAIRS: usize = 3;

#[derive(Debug)]
struct PendingPair {
    request: PairRequest,
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
        let capture = Capture::new(capture_backend, conn, config.release_bind());
        let emulation_backend = config.emulation_backend().map(|b| b.into());
        let emulation = Emulation::new(emulation_backend, listener);

        // create dns resolver
        let resolver = DnsResolver::new()?;

        let port = config.port();
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
                    }
                }
                event = next_control_event(&mut self.control) => self.handle_control_event(event),
                _ = discovery_changed(&mut self.discovery) => {
                    self.update_announced_ips();
                    self.broadcast_discovered();
                }
                _ = self.config.changed() => self.handle_config_change(),
                r = signal::ctrl_c() => break r.expect("failed to wait for CTRL+C"),
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
                self.update_pos(handle, pos);
                self.save_config();
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
                self.client_manager.set_offset(handle, offset);
                self.broadcast_client(handle);
                self.save_config();
            }
            FrontendRequest::UpdateLeaveHook(handle, leave_hook) => {
                self.update_leave_hook(handle, leave_hook)
            }
            FrontendRequest::SaveConfiguration => self.save_config(),
            FrontendRequest::Discover => self.broadcast_discovered(),
            FrontendRequest::Pair { fingerprint, pos } => self.start_pairing(fingerprint, pos),
            FrontendRequest::PairResponse {
                fingerprint,
                accept,
            } => self.answer_pairing(fingerprint, accept),
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
        let release_bind = self.config.release_bind();
        self.capture.set_release_bind(release_bind);
        let authorized_keys = self.config.authorized_fingerprints();
        self.authorized_keys
            .write()
            .unwrap()
            .clone_from(&authorized_keys);
        self.sync_frontend();
    }

    async fn handle_frontend_pending(&mut self) {
        while let Some(event) = self.pending_frontend_events.pop_front() {
            self.frontend_listener.broadcast(event).await;
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
                self.spawn_hook_command(handle, HookKind::Enter);
                if let (Some(control), Some(addr)) =
                    (&self.control, self.client_manager.active_addr(handle))
                {
                    control.send_clipboard(addr);
                }
            }
            ICaptureEvent::ClientLeft(handle) => {
                log::info!("leaving client {handle} ...");
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

    fn handle_control_event(&mut self, event: PairingEvent) {
        match event {
            PairingEvent::Request {
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
                    code,
                    pos: request.pos,
                });
                // a newer request from the same device replaces (declines) the old one
                self.pending_pairs
                    .insert(fingerprint, PendingPair { request, reply });
            }
            PairingEvent::Code { fingerprint, code } => {
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
            PairingEvent::Finished {
                fingerprint,
                pos,
                result,
            } => {
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
        let request = PairRequest {
            name: self.name.clone(),
            hostname: self.hostname.clone(),
            port: self.port,
            pos: pos.opposite(),
        };
        log::info!("asking {} to pair", peer.name);
        // the code is known once both sides exchanged their contributions,
        // see PairingEvent::Code
        control.pair(SocketAddr::new(ip, peer.port), fingerprint, pos, request);
    }

    fn answer_pairing(&mut self, fingerprint: String, accept: bool) {
        let Some(PendingPair { request, reply }) = self.pending_pairs.remove(&fingerprint) else {
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
        let status = if accept {
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
        self.update_pos(handle, pos);
        self.activate_client(handle);
        self.save_config();
        log::info!("paired with {name} ({hostname}), placed {pos}");
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
        self.authorized_keys.write().expect("lock").remove(&fp);
        self.emulation.disconnect(fp.clone());
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
        }
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

async fn next_control_event(control: &mut Option<Control>) -> PairingEvent {
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
