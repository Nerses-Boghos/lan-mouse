use futures::{Stream, StreamExt};
use lan_mouse_proto::{MAX_EVENT_SIZE, ProtoEvent};
use local_channel::mpsc::{Receiver, Sender, channel};
use rustls::pki_types::CertificateDer;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::Mutex as AsyncMutex,
    task::{JoinHandle, spawn_local},
};
use webrtc_dtls::{
    config::{ClientAuthType::RequireAnyClientCert, Config, ExtendedMasterSecretType},
    conn::DTLSConn,
    crypto::Certificate,
};
use webrtc_util::{
    Conn, Error,
    conn::{Listener, conn_udp_listener::ListenConfig},
};

use crate::crypto;

#[derive(Error, Debug)]
pub enum ListenerCreationError {
    #[error(transparent)]
    WebrtcUtil(#[from] webrtc_util::Error),
    #[error(transparent)]
    WebrtcDtls(#[from] webrtc_dtls::Error),
}

type ArcConn = Arc<dyn Conn + Send + Sync>;

pub(crate) enum ListenEvent {
    Msg {
        event: ProtoEvent,
        addr: SocketAddr,
    },
    Accept {
        addr: SocketAddr,
        fingerprint: String,
    },
    Rejected {
        fingerprint: String,
    },
}

pub(crate) struct LanMouseListener {
    listen_rx: Receiver<ListenEvent>,
    listen_tx: Sender<ListenEvent>,
    listen_task: JoinHandle<()>,
    conns: Rc<AsyncMutex<Vec<(SocketAddr, ArcConn)>>>,
    request_port_change: Sender<u16>,
    port_changed: Receiver<Result<u16, ListenerCreationError>>,
}

type VerifyPeerCertificateFn = Arc<
    dyn (Fn(&[Vec<u8>], &[CertificateDer<'static>]) -> Result<(), webrtc_dtls::Error>)
        + Send
        + Sync,
>;

impl LanMouseListener {
    pub(crate) async fn new(
        port: u16,
        cert: Certificate,
        authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    ) -> Result<Self, ListenerCreationError> {
        let (listen_tx, listen_rx) = channel();
        let (request_port_change, mut request_port_change_rx) = channel();
        let (port_changed_tx, port_changed) = channel();
        let connection_attempts: Arc<Mutex<VecDeque<String>>> = Default::default();

        let authorized = authorized_keys.clone();
        let verify_peer_certificate: Option<VerifyPeerCertificateFn> = {
            let connection_attempts = connection_attempts.clone();
            Some(Arc::new(
                move |certs: &[Vec<u8>], _chains: &[CertificateDer<'static>]| {
                    assert!(certs.len() == 1);
                    let fingerprints = certs
                        .iter()
                        .map(|c| crypto::generate_fingerprint(c))
                        .collect::<Vec<_>>();
                    if authorized
                        .read()
                        .expect("lock")
                        .contains_key(&fingerprints[0])
                    {
                        Ok(())
                    } else {
                        let fingerprint = fingerprints.into_iter().next().expect("fingerprint");
                        connection_attempts
                            .lock()
                            .expect("lock")
                            .push_back(fingerprint);
                        Err(webrtc_dtls::Error::ErrVerifyDataMismatch)
                    }
                },
            ))
        };
        let cfg = Config {
            certificates: vec![cert.clone()],
            extended_master_secret: ExtendedMasterSecretType::Require,
            client_auth: RequireAnyClientCert,
            verify_peer_certificate,
            ..Default::default()
        };

        let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
        let mut listener = listen(listen_addr).await?;

        let conns: Rc<AsyncMutex<Vec<(SocketAddr, ArcConn)>>> =
            Rc::new(AsyncMutex::new(Vec::new()));

        let conns_clone = conns.clone();
        let listen_task: JoinHandle<()> = {
            let listen_tx = listen_tx.clone();
            let connection_attempts = connection_attempts.clone();
            spawn_local(async move {
                loop {
                    tokio::select! {
                        c = listener.accept() => match c {
                            // The handshake runs on its own: done inside the
                            // accept loop, one stalled handshake held up all
                            // others, and the loop's workaround for that (a
                            // fresh accept every 2s) cut off handshakes still
                            // running, so devices on a slow network often
                            // couldn't connect at all.
                            Ok((conn, addr)) => {
                                spawn_local(handshake(
                                    conn,
                                    addr,
                                    cfg.clone(),
                                    conns_clone.clone(),
                                    listen_tx.clone(),
                                    connection_attempts.clone(),
                                ));
                            }
                            Err(e) => {
                                log::warn!("accept: {e:?}");
                                // e.g. the socket closed: don't spin
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        },
                        port = request_port_change_rx.recv() => {
                            let port = port.expect("channel closed");
                            let listen_addr = SocketAddr::new("0.0.0.0".parse().expect("invalid ip"), port);
                            match listen(listen_addr).await {
                                Ok(new_listener) => {
                                    let _ = listener.close().await;
                                    listener = new_listener;
                                    port_changed_tx.send(Ok(port)).expect("channel closed");
                                }
                                Err(e) => {
                                    log::warn!("unable to change port: {e}");
                                    port_changed_tx.send(Err(e.into())).expect("channel closed");
                                }
                            };
                        },
                    };
                }
            })
        };

        Ok(Self {
            conns,
            listen_rx,
            listen_tx,
            listen_task,
            port_changed,
            request_port_change,
        })
    }

    pub(crate) fn request_port_change(&mut self, port: u16) {
        self.request_port_change.send(port).expect("channel closed");
    }

    pub(crate) async fn port_changed(&mut self) -> Result<u16, ListenerCreationError> {
        self.port_changed.recv().await.expect("channel closed")
    }

    pub(crate) async fn terminate(&mut self) {
        self.listen_task.abort();
        let conns = self.conns.lock().await;
        for (_, conn) in conns.iter() {
            let _ = conn.close().await;
        }
        self.listen_tx.close();
    }

    pub(crate) async fn reply(&self, addr: SocketAddr, event: ProtoEvent) {
        log::trace!("reply {event} >=>=>=>=>=> {addr}");
        let (buf, len): ([u8; MAX_EVENT_SIZE], usize) = event.into();
        let conns = self.conns.lock().await;
        for (a, conn) in conns.iter() {
            if *a == addr {
                let _ = conn.send(&buf[..len]).await;
            }
        }
    }

    /// Close every connection from the device with `fingerprint` and return
    /// their addresses. Authorization is only checked during the handshake,
    /// so revoking a device must also end the connections it already has.
    pub(crate) async fn disconnect(&self, fingerprint: &str) -> Vec<SocketAddr> {
        let conns = self.conns.lock().await.clone();
        let mut closed = vec![];
        for (addr, conn) in conns {
            if self.get_certificate_fingerprint(addr).await.as_deref() == Some(fingerprint) {
                let _ = conn.close().await;
                closed.push(addr);
            }
        }
        closed
    }

    pub(crate) async fn get_certificate_fingerprint(&self, addr: SocketAddr) -> Option<String> {
        if let Some(conn) = self
            .conns
            .lock()
            .await
            .iter()
            .find(|(a, _)| *a == addr)
            .map(|(_, c)| c.clone())
        {
            let conn: &DTLSConn = conn.as_any().downcast_ref().expect("dtls conn");
            let certs = conn.connection_state().await.peer_certificates;
            let cert = certs.first()?;
            let fingerprint = crypto::generate_fingerprint(cert);
            Some(fingerprint)
        } else {
            None
        }
    }
}

impl Stream for LanMouseListener {
    type Item = ListenEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.listen_rx.poll_next_unpin(cx)
    }
}

/// Listens for DTLS handshakes on UDP `addr`: datagrams from a new address
/// open a connection only if they are handshake records.
async fn listen(addr: SocketAddr) -> Result<impl Listener, webrtc_util::Error> {
    /// the DTLS record content type of handshake messages
    const HANDSHAKE: u8 = 22;
    let mut config = ListenConfig {
        accept_filter: Some(Box::new(|packet: &[u8]| {
            let handshake = packet.first() == Some(&HANDSHAKE);
            Box::pin(async move { handshake })
        })),
        ..Default::default()
    };
    config.listen(addr).await
}

/// How long a device gets to complete the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Completes the DTLS handshake with a device that just reached out, then
/// reads from it.
async fn handshake(
    conn: ArcConn,
    addr: SocketAddr,
    cfg: Config,
    conns: Rc<AsyncMutex<Vec<(SocketAddr, ArcConn)>>>,
    listen_tx: Sender<ListenEvent>,
    connection_attempts: Arc<Mutex<VecDeque<String>>>,
) {
    let dtls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        DTLSConn::new(conn.clone(), cfg, false, None),
    )
    .await;
    let dtls = match dtls {
        Ok(Ok(dtls)) => dtls,
        Ok(Err(webrtc_dtls::Error::ErrVerifyDataMismatch)) => {
            if let Some(fingerprint) = connection_attempts.lock().expect("lock").pop_front() {
                listen_tx
                    .send(ListenEvent::Rejected { fingerprint })
                    .expect("channel closed");
            }
            // forget the address, so its next attempt starts afresh
            let _ = conn.close().await;
            return;
        }
        Ok(Err(e)) => {
            log::warn!("handshake with {addr} failed: {e}");
            let _ = conn.close().await;
            return;
        }
        Err(_) => {
            log::warn!("handshake with {addr} timed out");
            let _ = conn.close().await;
            return;
        }
    };
    log::info!("dtls client connected, ip: {addr}");
    let certs = dtls.connection_state().await.peer_certificates;
    let Some(cert) = certs.first() else {
        let _ = dtls.close().await;
        return;
    };
    let fingerprint = crypto::generate_fingerprint(cert);
    let dtls: ArcConn = Arc::new(dtls);
    conns.lock().await.push((addr, dtls.clone()));
    listen_tx
        .send(ListenEvent::Accept { addr, fingerprint })
        .expect("channel closed");
    let _ = read_loop(conns, addr, dtls, listen_tx).await;
}

async fn read_loop(
    conns: Rc<AsyncMutex<Vec<(SocketAddr, ArcConn)>>>,
    addr: SocketAddr,
    conn: ArcConn,
    dtls_tx: Sender<ListenEvent>,
) -> Result<(), Error> {
    let mut b = [0u8; MAX_EVENT_SIZE];

    while conn.recv(&mut b).await.is_ok() {
        match b.try_into() {
            Ok(event) => dtls_tx
                .send(ListenEvent::Msg { event, addr })
                .expect("channel closed"),
            Err(e) => {
                // Skip the malformed/unknown datagram and keep
                // listening. Each DTLS recv returns one full
                // datagram, so a parse error here can't desync a
                // stream; the next call gets a fresh, framed
                // message. This makes the protocol forward-
                // compatible: a peer running a newer Lan Mouse
                // version can introduce additional event types
                // and old peers will simply ignore them rather
                // than dropping the connection.
                log::debug!("ignoring undecodable event from {addr}: {e}");
            }
        }
    }
    log::info!("dtls client disconnected {addr:?}");
    let mut conns = conns.lock().await;
    let index = conns
        .iter()
        .position(|(a, _)| *a == addr)
        .expect("connection not found");
    conns.remove(index);
    Ok(())
}
