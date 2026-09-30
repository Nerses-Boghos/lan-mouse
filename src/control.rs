//! Control channel between Lan Mouse devices, for everything that doesn't fit
//! the fixed-size UDP/DTLS input protocol: clipboard contents, pairing and
//! the screen arrangement.
//!
//! It runs over TCP/TLS on the same port as the input channel. Both sides
//! present their Lan Mouse certificate. Clipboard transfers only happen
//! between devices whose fingerprints are authorized (in both directions);
//! the only message an unauthorized device may send is a pairing request,
//! which the user has to confirm.
//!
//! Each connection carries one request and at most one reply, framed as
//! `kind: u8`, `len: u32` (big endian), `payload`.

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use lan_mouse_ipc::{Monitor, Position};
use local_channel::mpsc::{Receiver, Sender, channel};
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, spawn_local},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webrtc_dtls::crypto::Certificate;

use crate::{clipboard, crypto};

/// Largest message accepted or sent.
const MAX_SIZE: usize = 16 * 1024 * 1024;
/// Largest message accepted from a device that isn't paired: a pairing
/// request is a few hundred bytes, and strangers must not make us allocate.
const MAX_UNPAIRED_SIZE: usize = 4096;
/// Gives up on a peer that does not complete a transfer in time.
const TIMEOUT: Duration = Duration::from_secs(5);
/// How long to assume a peer still has the clipboard content it last
/// exchanged with us, so crossing back and forth doesn't resend it.
const CLIPBOARD_MEMORY: Duration = Duration::from_secs(10);
/// How long a pairing request waits for the user to answer it.
pub(crate) const PAIR_TIMEOUT: Duration = Duration::from_secs(120);

const KIND_CLIPBOARD: u8 = 1;
const KIND_PAIR_REQUEST: u8 = 2;
const KIND_PAIR_REPLY: u8 = 3;
const KIND_PAIR_COMMIT: u8 = 4;
const KIND_PAIR_NONCE: u8 = 5;
const KIND_PAIR_REVEAL: u8 = 6;
const KIND_PAIR_CONFIRM: u8 = 7;
/// Sent instead of a commitment while pairing attempts are rate limited.
const KIND_PAIR_BUSY: u8 = 8;
const KIND_LAYOUT: u8 = 9;

/// Largest [`Layout`] accepted: a few monitors are a few hundred bytes.
const MAX_LAYOUT_SIZE: usize = 64 * 1024;

/// At most this many pairing code exchanges per [`EXCHANGE_WINDOW`], across
/// all devices. Each exchange gives a fresh random code; unlimited exchanges
/// would let someone in the middle retry until a code matches.
const MAX_EXCHANGES: usize = 3;
const EXCHANGE_WINDOW: Duration = Duration::from_secs(60);

/// Random contribution of each side to the pairing code.
const NONCE_LEN: usize = 32;
type Nonce = [u8; NONCE_LEN];

#[derive(Debug, Error)]
pub(crate) enum ControlError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("peer {0} is not authorized")]
    Unauthorized(String),
    #[error("peer presented fingerprint {0}, not the expected one")]
    WrongPeer(String),
    #[error("message of {0} bytes exceeds the {MAX_SIZE} byte limit")]
    TooLarge(usize),
    #[error("unexpected message kind {0}")]
    UnexpectedKind(u8),
    #[error("the other device broke its pairing commitment (someone may be interfering)")]
    CommitMismatch,
    #[error("message of {0} bytes has the wrong length")]
    BadLength(usize),
    #[error("the other device refuses pairing attempts for a minute; try again then")]
    TooManyAttempts,
    #[error("cancelled on this device")]
    Cancelled,
    #[error("timed out")]
    Timeout,
}

/// Sent by the device that initiates pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PairRequest {
    pub(crate) name: String,
    pub(crate) hostname: String,
    /// the requester's Lan Mouse port
    pub(crate) port: u16,
    /// where the requesting device sits relative to the receiving one
    pub(crate) pos: Position,
}

/// The answer to a [`PairRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PairReply {
    pub(crate) accepted: bool,
    pub(crate) name: String,
    pub(crate) hostname: String,
    /// the replying device's Lan Mouse port
    pub(crate) port: u16,
}

/// A device's monitors and its arrangement with the receiving device, sent
/// whenever either changes: both devices keep the same arrangement, seen from
/// their own side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Layout {
    /// the sender's monitors, in its logical pixels
    pub(crate) monitors: Vec<Monitor>,
    /// where the sender sits relative to the receiver
    pub(crate) pos: Position,
    /// where the sender's screen starts along the receiver's edge, in
    /// pixels; `None` maps the edges proportionally
    pub(crate) offset: Option<i32>,
    /// when this arrangement was made, in milliseconds since the Unix
    /// epoch: the newer one wins
    pub(crate) arranged_at: u64,
}

pub(crate) enum ControlEvent {
    /// A device asks to pair. Answer through `reply`; dropping it declines.
    /// Accepting only trusts the device once it confirms too, see
    /// [`ControlEvent::Confirmed`].
    Request {
        fingerprint: String,
        request: PairRequest,
        /// shown to the user, who compares it with the other device's
        code: String,
        reply: oneshot::Sender<PairReply>,
    },
    /// After this device accepted a [`ControlEvent::Request`], the other
    /// device's user confirmed (or rejected) the code as well.
    Confirmed {
        fingerprint: String,
        request: PairRequest,
        confirmed: bool,
    },
    /// The code of a pairing started with [`Control::pair`], known once
    /// both sides exchanged their contributions; the other device shows the
    /// same code while asking its user.
    Code { fingerprint: String, code: String },
    /// A paired device sent its monitors and arrangement.
    Layout { fingerprint: String, layout: Layout },
    /// A pairing started with [`Control::pair`] completed.
    Finished {
        fingerprint: String,
        /// where the other device sits relative to this one
        pos: Position,
        result: Result<PairReply, ControlError>,
    },
}

type AuthorizedKeys = Arc<RwLock<HashMap<String, String>>>;
/// Per peer address: hash of the clipboard content last exchanged, and when.
type PeerClipboards = Rc<RefCell<HashMap<std::net::IpAddr, ([u8; 32], Instant)>>>;

pub(crate) struct Control {
    /// this device's certificate fingerprint
    own_fingerprint: String,
    /// the TCP port listened on (only read by tests, which bind port 0)
    #[cfg_attr(not(test), allow(dead_code))]
    port: u16,
    acceptor: TlsAcceptor,
    handler: Handler,
    accept_task: JoinHandle<()>,
    connector: TlsConnector,
    authorized_keys: AuthorizedKeys,
    clipboard_enabled: bool,
    /// hash of the clipboard each peer (by ip) is known to have
    peer_clipboard: PeerClipboards,
    event_tx: Sender<ControlEvent>,
    event_rx: Receiver<ControlEvent>,
}

impl Control {
    /// Start listening on TCP `port`.
    pub(crate) async fn new(
        port: u16,
        cert: &Certificate,
        authorized_keys: AuthorizedKeys,
        clipboard_enabled: bool,
    ) -> Result<Self, ControlError> {
        let (acceptor, connector) = tls(cert)?;
        let listener = TcpListener::bind(SocketAddr::new([0, 0, 0, 0].into(), port)).await?;
        let port = listener.local_addr()?.port();
        let (event_tx, event_rx) = channel();
        let peer_clipboard = Rc::new(RefCell::new(HashMap::new()));
        let own_fingerprint = crypto::certificate_fingerprint(cert);
        let handler = Handler {
            own_fingerprint: own_fingerprint.clone(),
            exchanges: Default::default(),
            authorized_keys: authorized_keys.clone(),
            clipboard_enabled,
            peer_clipboard: peer_clipboard.clone(),
            event_tx: event_tx.clone(),
        };
        let accept_task = spawn_local(accept_loop(listener, acceptor.clone(), handler.clone()));
        log::info!("control channel listening on tcp port {port}");

        Ok(Self {
            own_fingerprint,
            port,
            acceptor,
            handler,
            accept_task,
            connector,
            authorized_keys,
            clipboard_enabled,
            peer_clipboard,
            event_tx,
            event_rx,
        })
    }

    /// Move to another TCP port, following the input channel. Binding
    /// happens in the background; failures are logged.
    pub(crate) fn rebind(&mut self, port: u16) {
        self.accept_task.abort();
        self.port = port;
        let (acceptor, handler) = (self.acceptor.clone(), self.handler.clone());
        self.accept_task = spawn_local(async move {
            match TcpListener::bind(SocketAddr::new([0, 0, 0, 0].into(), port)).await {
                Ok(listener) => {
                    log::info!("control channel listening on tcp port {port}");
                    accept_loop(listener, acceptor, handler).await
                }
                Err(e) => log::warn!("control channel can't listen on tcp port {port}: {e}"),
            }
        });
    }

    #[cfg(test)]
    fn port(&self) -> u16 {
        self.port
    }

    pub(crate) async fn event(&mut self) -> ControlEvent {
        self.event_rx.recv().await.expect("channel closed")
    }

    /// Send the local clipboard to `addr` in the background, unless that peer
    /// already has exactly this content.
    pub(crate) fn send_clipboard(&self, addr: SocketAddr) {
        if !self.clipboard_enabled {
            return;
        }
        let connector = self.connector.clone();
        let authorized_keys = self.authorized_keys.clone();
        let peer_clipboard = self.peer_clipboard.clone();
        spawn_local(async move {
            let text = match clipboard::read().await {
                Ok(Some(text)) if !text.is_empty() => text,
                Ok(_) => return,
                Err(e) => {
                    log::warn!("could not read clipboard: {e}");
                    return;
                }
            };
            let hash = digest(&text);
            // Skip resending what the peer got moments ago (crossing back and
            // forth). Only briefly: it may have copied something else since.
            if peer_clipboard
                .borrow()
                .get(&addr.ip())
                .is_some_and(|(h, at)| *h == hash && at.elapsed() < CLIPBOARD_MEMORY)
            {
                return;
            }
            let transfer = async {
                let (mut tls, fingerprint) = connect(&connector, addr).await?;
                check_authorized(&fingerprint, &authorized_keys)?;
                write_frame(&mut tls, KIND_CLIPBOARD, &text).await?;
                tls.shutdown().await?;
                Ok::<_, ControlError>(())
            };
            match timeout(TIMEOUT, transfer).await {
                Ok(()) => {
                    log::info!("sent clipboard ({} bytes) to {addr}", text.len());
                    peer_clipboard
                        .borrow_mut()
                        .insert(addr.ip(), (hash, Instant::now()));
                }
                Err(e) => log::warn!("could not send clipboard to {addr}: {e}"),
            }
        });
    }

    /// Send `layout` to the paired device at `addr`, whose certificate must
    /// match `fingerprint`, in the background.
    pub(crate) fn send_layout(&self, addr: SocketAddr, fingerprint: String, layout: Layout) {
        let connector = self.connector.clone();
        let authorized_keys = self.authorized_keys.clone();
        spawn_local(async move {
            let transfer = async {
                let payload = serde_json::to_vec(&layout)?;
                let (mut tls, peer) = connect(&connector, addr).await?;
                if peer != fingerprint {
                    return Err(ControlError::WrongPeer(peer));
                }
                check_authorized(&peer, &authorized_keys)?;
                write_frame(&mut tls, KIND_LAYOUT, &payload).await?;
                tls.shutdown().await?;
                Ok::<_, ControlError>(())
            };
            match timeout(TIMEOUT, transfer).await {
                Ok(()) => log::info!("sent the screen arrangement to {addr}"),
                Err(e) => log::warn!("could not send the screen arrangement to {addr}: {e}"),
            }
        });
    }

    /// Ask the device at `addr`, whose certificate must match `fingerprint`,
    /// to pair; it will sit at `pos` relative to this one.
    ///
    /// Once the code is known ([`ControlEvent::Code`]) this device's user has
    /// to confirm it too, through `confirmed`: both users compare the codes,
    /// and neither device trusts the other before both did. The outcome
    /// arrives as [`ControlEvent::Finished`]; `Ok` with an accepted reply
    /// means both confirmed.
    pub(crate) fn pair(
        &self,
        addr: SocketAddr,
        fingerprint: String,
        pos: Position,
        request: PairRequest,
        confirmed: oneshot::Receiver<bool>,
    ) {
        let connector = self.connector.clone();
        let event_tx = self.event_tx.clone();
        let own_fingerprint = self.own_fingerprint.clone();
        spawn_local(async move {
            let result = async {
                let (mut tls, presented) = connect(&connector, addr).await?;
                // The advertised fingerprint is what the user picked; make
                // sure the device answering really holds that certificate.
                if presented != fingerprint {
                    return Err(ControlError::WrongPeer(presented));
                }
                write_frame(&mut tls, KIND_PAIR_REQUEST, &serde_json::to_vec(&request)?).await?;
                let code = timeout(
                    TIMEOUT,
                    requester_exchange(&mut tls, &own_fingerprint, &fingerprint),
                )
                .await?;
                let _ = event_tx.send(ControlEvent::Code {
                    fingerprint: fingerprint.clone(),
                    code,
                });
                // The other device's user answers within PAIR_TIMEOUT; wait a
                // little longer, so an answer at the last moment isn't lost.
                let reply: PairReply = timeout(PAIR_TIMEOUT + TIMEOUT, async {
                    Ok(serde_json::from_slice(
                        &read_frame(&mut tls, KIND_PAIR_REPLY).await?,
                    )?)
                })
                .await?;
                if !reply.accepted {
                    return Ok(reply);
                }
                // our user's side of the comparison (possibly given already)
                let confirmed = matches!(
                    tokio::time::timeout(PAIR_TIMEOUT, confirmed).await,
                    Ok(Ok(true))
                );
                write_frame(&mut tls, KIND_PAIR_CONFIRM, &[confirmed as u8]).await?;
                tls.shutdown().await?;
                if confirmed {
                    Ok(reply)
                } else {
                    Err(ControlError::Cancelled)
                }
            }
            .await;
            let _ = event_tx.send(ControlEvent::Finished {
                fingerprint,
                pos,
                result,
            });
        });
    }
}

/// Handles incoming connections.
#[derive(Clone)]
struct Handler {
    own_fingerprint: String,
    /// when recent pairing code exchanges started, see [`MAX_EXCHANGES`]
    exchanges: Rc<RefCell<VecDeque<Instant>>>,
    authorized_keys: AuthorizedKeys,
    clipboard_enabled: bool,
    peer_clipboard: PeerClipboards,
    event_tx: Sender<ControlEvent>,
}

impl Handler {
    async fn handle<S>(
        &self,
        tls: &mut S,
        fingerprint: String,
        addr: SocketAddr,
    ) -> Result<(), ControlError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (kind, len) = timeout(TIMEOUT, read_header(tls)).await?;
        // Decide what this peer may send before reading (and allocating) it.
        let paired = check_authorized(&fingerprint, &self.authorized_keys).is_ok();
        match kind {
            KIND_CLIPBOARD | KIND_LAYOUT if !paired => {
                return Err(ControlError::Unauthorized(fingerprint));
            }
            KIND_LAYOUT if len > MAX_LAYOUT_SIZE => return Err(ControlError::TooLarge(len)),
            KIND_CLIPBOARD | KIND_LAYOUT | KIND_PAIR_REQUEST => {}
            kind => return Err(ControlError::UnexpectedKind(kind)),
        }
        let limit = if paired { MAX_SIZE } else { MAX_UNPAIRED_SIZE };
        if len > limit {
            return Err(ControlError::TooLarge(len));
        }
        let payload = timeout(TIMEOUT, read_payload(tls, len)).await?;
        match kind {
            KIND_CLIPBOARD => {
                if !self.clipboard_enabled {
                    return Ok(());
                }
                timeout(TIMEOUT, async { Ok(clipboard::write(&payload).await?) }).await?;
                // the sender has this content now, no need to send it back
                self.peer_clipboard
                    .borrow_mut()
                    .insert(addr.ip(), (digest(&payload), Instant::now()));
                log::info!("received clipboard ({} bytes) from {addr}", payload.len());
                Ok(())
            }
            KIND_LAYOUT => {
                let layout: Layout = serde_json::from_slice(&payload)?;
                let _ = self.event_tx.send(ControlEvent::Layout {
                    fingerprint,
                    layout,
                });
                Ok(())
            }
            KIND_PAIR_REQUEST => {
                let request: PairRequest = serde_json::from_slice(&payload)?;
                if let Err(e) = self.count_exchange() {
                    // tell the requester why, instead of just hanging up
                    write_frame(tls, KIND_PAIR_BUSY, &[]).await?;
                    tls.shutdown().await?;
                    return Err(e);
                }
                let code = timeout(
                    TIMEOUT,
                    responder_exchange(tls, &fingerprint, &self.own_fingerprint),
                )
                .await?;
                log::info!("{} ({addr}) asks to pair", request.name);
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = self.event_tx.send(ControlEvent::Request {
                    fingerprint: fingerprint.clone(),
                    request: request.clone(),
                    code,
                    reply: reply_tx,
                });
                let reply = match tokio::time::timeout(PAIR_TIMEOUT, reply_rx).await {
                    Ok(Ok(reply)) => reply,
                    // no answer in time, or the request was dropped: decline
                    _ => PairReply {
                        accepted: false,
                        name: String::new(),
                        hostname: String::new(),
                        port: 0,
                    },
                };
                write_frame(tls, KIND_PAIR_REPLY, &serde_json::to_vec(&reply)?).await?;
                if !reply.accepted {
                    tls.shutdown().await?;
                    return Ok(());
                }
                // Our user accepted; trust the other device only once its user
                // confirmed the code too. It waits PAIR_TIMEOUT for them.
                let confirmed = timeout(PAIR_TIMEOUT + TIMEOUT, async {
                    Ok(read_sized_frame(tls, KIND_PAIR_CONFIRM, 1).await?[0] == 1)
                })
                .await
                .unwrap_or(false);
                let _ = self.event_tx.send(ControlEvent::Confirmed {
                    fingerprint,
                    request,
                    confirmed,
                });
                Ok(())
            }
            kind => Err(ControlError::UnexpectedKind(kind)),
        }
    }

    /// Allow a pairing code exchange if fewer than [`MAX_EXCHANGES`] started
    /// in the last [`EXCHANGE_WINDOW`].
    fn count_exchange(&self) -> Result<(), ControlError> {
        let mut exchanges = self.exchanges.borrow_mut();
        while exchanges
            .front()
            .is_some_and(|t| t.elapsed() >= EXCHANGE_WINDOW)
        {
            exchanges.pop_front();
        }
        if exchanges.len() >= MAX_EXCHANGES {
            return Err(ControlError::TooManyAttempts);
        }
        exchanges.push_back(Instant::now());
        Ok(())
    }
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, handler: Handler) {
    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("control listener: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        spawn_local(async move {
            let result = async {
                let mut tls = timeout(TIMEOUT, async { Ok(acceptor.accept(tcp).await?) }).await?;
                let fingerprint = peer_fingerprint(tls.get_ref().1.peer_certificates());
                handler.handle(&mut tls, fingerprint, addr).await
            };
            if let Err(e) = result.await {
                log::warn!("control connection from {addr}: {e}");
            }
        });
    }
}

async fn connect(
    connector: &TlsConnector,
    addr: SocketAddr,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, String), ControlError> {
    let tcp = timeout(TIMEOUT, async { Ok(TcpStream::connect(addr).await?) }).await?;
    let tls = timeout(TIMEOUT, async {
        Ok(connector
            .connect(ServerName::IpAddress(addr.ip().into()), tcp)
            .await?)
    })
    .await?;
    let fingerprint = peer_fingerprint(tls.get_ref().1.peer_certificates());
    Ok((tls, fingerprint))
}

async fn timeout<T>(
    duration: Duration,
    f: impl Future<Output = Result<T, ControlError>>,
) -> Result<T, ControlError> {
    tokio::time::timeout(duration, f)
        .await
        .map_err(|_| ControlError::Timeout)?
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    kind: u8,
    payload: &[u8],
) -> Result<(), ControlError> {
    if payload.len() > MAX_SIZE {
        return Err(ControlError::TooLarge(payload.len()));
    }
    stream.write_u8(kind).await?;
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// A frame's kind and payload length, without reading the payload.
async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, usize), ControlError> {
    let kind = stream.read_u8().await?;
    let len = stream.read_u32().await? as usize;
    Ok((kind, len))
}

async fn read_payload<S: AsyncRead + Unpin>(
    stream: &mut S,
    len: usize,
) -> Result<Vec<u8>, ControlError> {
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn read_any_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u8, Vec<u8>), ControlError> {
    let (kind, len) = read_header(stream).await?;
    if len > MAX_SIZE {
        return Err(ControlError::TooLarge(len));
    }
    Ok((kind, read_payload(stream, len).await?))
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    expected: u8,
) -> Result<Vec<u8>, ControlError> {
    let (kind, payload) = read_any_frame(stream).await?;
    if kind == expected {
        Ok(payload)
    } else {
        Err(ControlError::UnexpectedKind(kind))
    }
}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn peer_fingerprint(certs: Option<&[CertificateDer<'_>]>) -> String {
    certs
        .and_then(|c| c.first())
        .map(|c| crypto::generate_fingerprint(c))
        .unwrap_or_default()
}

fn check_authorized(
    fingerprint: &str,
    authorized_keys: &AuthorizedKeys,
) -> Result<(), ControlError> {
    if authorized_keys
        .read()
        .expect("lock")
        .contains_key(fingerprint)
    {
        Ok(())
    } else {
        Err(ControlError::Unauthorized(fingerprint.to_owned()))
    }
}

// Pairing code exchange (the "numeric comparison" of Bluetooth pairing):
//
//   requester                         responder
//       ---- PairRequest ------------------>
//       <--- commit = H(nonce_b) -----------   responder commits first
//       ---- nonce_a ---------------------->
//       <--- nonce_b (reveal) --------------   requester checks the commitment
//
// Both derive the code from both certificate fingerprints and both nonces.
// Someone in the middle (with their own certificates towards each side)
// would have to commit to nonce_b before learning nonce_a, so they can't
// search for certificates or nonces that make both screens show the same
// code: they get one guess in a million, and a wrong guess shows up as
// different codes.

/// Requester side of the exchange, after sending the request. Returns the
/// code.
async fn requester_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    requester: &str,
    responder: &str,
) -> Result<String, ControlError> {
    let commitment = match read_small_frame(stream, KIND_PAIR_COMMIT).await {
        Err(ControlError::UnexpectedKind(KIND_PAIR_BUSY)) => {
            return Err(ControlError::TooManyAttempts);
        }
        commitment => commitment?,
    };
    let nonce_a = random_nonce();
    write_frame(stream, KIND_PAIR_NONCE, &nonce_a).await?;
    let nonce_b = read_small_frame(stream, KIND_PAIR_REVEAL).await?;
    if commit(&nonce_b) != commitment {
        return Err(ControlError::CommitMismatch);
    }
    Ok(pairing_code(requester, responder, &nonce_a, &nonce_b))
}

/// Responder side of the exchange, after receiving the request. Returns the
/// code.
async fn responder_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    requester: &str,
    responder: &str,
) -> Result<String, ControlError> {
    let nonce_b = random_nonce();
    write_frame(stream, KIND_PAIR_COMMIT, &commit(&nonce_b)).await?;
    let nonce_a = read_small_frame(stream, KIND_PAIR_NONCE).await?;
    write_frame(stream, KIND_PAIR_REVEAL, &nonce_b).await?;
    Ok(pairing_code(requester, responder, &nonce_a, &nonce_b))
}

/// A 32 byte frame of the given kind (nonces and commitments).
async fn read_small_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    expected: u8,
) -> Result<Nonce, ControlError> {
    let payload = read_sized_frame(stream, expected, NONCE_LEN).await?;
    Ok(payload.try_into().expect("length checked"))
}

/// A frame of the given kind and exact length.
async fn read_sized_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    expected: u8,
    size: usize,
) -> Result<Vec<u8>, ControlError> {
    let (kind, len) = read_header(stream).await?;
    if kind != expected {
        return Err(ControlError::UnexpectedKind(kind));
    }
    if len != size {
        return Err(ControlError::BadLength(len));
    }
    read_payload(stream, len).await
}

fn random_nonce() -> Nonce {
    let mut nonce = [0u8; NONCE_LEN];
    ring::default_provider()
        .secure_random
        .fill(&mut nonce)
        .expect("the system's random number generator failed");
    nonce
}

fn commit(nonce: &Nonce) -> Nonce {
    let mut hash = Sha256::new();
    hash.update(b"lan-mouse pairing commitment\n");
    hash.update(nonce);
    hash.finalize().into()
}

/// The six digit code both devices show while pairing.
fn pairing_code(requester: &str, responder: &str, nonce_a: &Nonce, nonce_b: &Nonce) -> String {
    let mut hash = Sha256::new();
    hash.update(format!("lan-mouse pairing v2\n{requester}\n{responder}\n"));
    hash.update(nonce_a);
    hash.update(nonce_b);
    let hash = hash.finalize();
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// TLS server and client sides, both authenticating with `cert`.
fn tls(cert: &Certificate) -> Result<(TlsAcceptor, TlsConnector), rustls::Error> {
    let provider = Arc::new(ring::default_provider());
    let key = PrivatePkcs8KeyDer::from(cert.private_key.serialized_der.clone());
    let (chain, key): (_, PrivateKeyDer) = (cert.certificate.clone(), key.into());
    let verifier = Arc::new(AnyCert(provider.signature_verification_algorithms));

    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(chain.clone(), key.clone_key())?;
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)?;

    Ok((
        TlsAcceptor::from(Arc::new(server_config)),
        TlsConnector::from(Arc::new(client_config)),
    ))
}

/// Accepts any certificate during the handshake (Lan Mouse certificates are
/// self-signed) while still checking the handshake signatures. Whether a
/// peer is allowed is decided afterwards by its fingerprint.
#[derive(Debug)]
struct AnyCert(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

impl ClientCertVerifier for AnyCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{io::duplex, task::LocalSet};

    fn cert() -> Certificate {
        Certificate::generate_self_signed(["ignored".to_owned()]).expect("certificate")
    }

    fn keys(authorized: &[&Certificate]) -> AuthorizedKeys {
        let keys = authorized
            .iter()
            .map(|c| (crypto::certificate_fingerprint(c), "peer".to_owned()))
            .collect();
        Arc::new(RwLock::new(keys))
    }

    fn request() -> PairRequest {
        PairRequest {
            name: "requester".to_owned(),
            hostname: "requester.local".to_owned(),
            port: 4242,
            pos: Position::Left,
        }
    }

    /// What a pairing between two devices ended with.
    struct Outcome {
        /// what the requesting device learned
        requester: Result<PairReply, ControlError>,
        /// whether the responding device was told the requester confirmed
        /// (`None`: it never got that far)
        responder_confirmed: Option<bool>,
    }

    /// `a` asks `b` to pair, expecting `b`'s certificate unless `impostor`.
    /// `b`'s user answers `accept` (`None`: drops the request), `a`'s user
    /// confirms the code with `confirm`.
    async fn pair(impostor: bool, accept: Option<bool>, confirm: bool) -> Outcome {
        let (a_cert, b_cert) = (cert(), cert());
        let mut a = Control::new(0, &a_cert, keys(&[]), false).await.expect("a");
        let mut b = Control::new(0, &b_cert, keys(&[]), false).await.expect("b");
        let b_addr = SocketAddr::new([127, 0, 0, 1].into(), b.port());
        let expected = if impostor { cert() } else { b_cert.clone() };
        let (confirm_tx, confirm_rx) = oneshot::channel();
        a.pair(
            b_addr,
            crypto::certificate_fingerprint(&expected),
            Position::Right,
            request(),
            confirm_rx,
        );
        // a's user may confirm before b's user answers: order doesn't matter
        let _ = confirm_tx.send(confirm);

        let answer = async {
            let ControlEvent::Request {
                fingerprint,
                request: received,
                code,
                reply,
            } = b.event().await
            else {
                panic!("expected a pair request");
            };
            assert_eq!(fingerprint, crypto::certificate_fingerprint(&a_cert));
            assert_eq!(received, request());
            match accept {
                Some(accepted) => {
                    let _ = reply.send(PairReply {
                        accepted,
                        name: "receiver".to_owned(),
                        hostname: "receiver.local".to_owned(),
                        port: 4242,
                    });
                }
                None => drop(reply),
            }
            code
        };
        let mut event = a.event().await;
        if !impostor {
            let ControlEvent::Code { code, .. } = event else {
                panic!("expected the pairing code");
            };
            // both screens show the same code
            assert_eq!(answer.await, code);
            event = a.event().await;
        } else {
            drop(answer);
        }
        let ControlEvent::Finished { result, pos, .. } = event else {
            panic!("expected the pairing to finish");
        };
        assert_eq!(pos, Position::Right);
        let responder_confirmed = if !impostor && accept == Some(true) {
            let ControlEvent::Confirmed { confirmed, .. } = b.event().await else {
                panic!("expected the confirmation");
            };
            Some(confirmed)
        } else {
            None
        };
        Outcome {
            requester: result,
            responder_confirmed,
        }
    }

    #[tokio::test]
    async fn pairing_needs_both_users() {
        LocalSet::new()
            .run_until(async {
                let outcome = pair(false, Some(true), true).await;
                let reply = outcome.requester.expect("reply");
                assert!(reply.accepted);
                assert_eq!(reply.hostname, "receiver.local");
                assert_eq!(outcome.responder_confirmed, Some(true));
            })
            .await;
    }

    #[tokio::test]
    async fn the_requester_can_reject_the_code() {
        LocalSet::new()
            .run_until(async {
                // b's user accepted, but a's user says the codes differ:
                // neither side may trust the other
                let outcome = pair(false, Some(true), false).await;
                assert!(matches!(outcome.requester, Err(ControlError::Cancelled)));
                assert_eq!(outcome.responder_confirmed, Some(false));
            })
            .await;
    }

    #[tokio::test]
    async fn pairing_is_declined() {
        LocalSet::new()
            .run_until(async {
                let outcome = pair(false, Some(false), true).await;
                assert!(!outcome.requester.expect("reply").accepted);
                // dropping the request without an answer declines too
                let outcome = pair(false, None, true).await;
                assert!(!outcome.requester.expect("reply").accepted);
            })
            .await;
    }

    #[tokio::test]
    async fn pairing_refuses_an_impostor() {
        LocalSet::new()
            .run_until(async {
                let outcome = pair(true, Some(true), true).await;
                assert!(matches!(outcome.requester, Err(ControlError::WrongPeer(_))));
            })
            .await;
    }

    #[tokio::test]
    async fn unpaired_devices_cannot_send_the_clipboard() {
        LocalSet::new()
            .run_until(async {
                let (event_tx, _event_rx) = channel();
                let handler = Handler {
                    own_fingerprint: "me".to_owned(),
                    exchanges: Default::default(),
                    authorized_keys: keys(&[]),
                    clipboard_enabled: true,
                    peer_clipboard: Default::default(),
                    event_tx,
                };
                let (mut client, mut server) = duplex(1024);
                write_frame(&mut client, KIND_CLIPBOARD, b"secret")
                    .await
                    .expect("write");
                let addr = SocketAddr::new([127, 0, 0, 1].into(), 1);
                let result = handler
                    .handle(&mut server, "stranger".to_owned(), addr)
                    .await;
                assert!(matches!(result, Err(ControlError::Unauthorized(_))));
            })
            .await;
    }

    #[tokio::test]
    async fn strangers_cannot_make_us_allocate() {
        LocalSet::new()
            .run_until(async {
                let (event_tx, _event_rx) = channel();
                let handler = Handler {
                    own_fingerprint: "me".to_owned(),
                    exchanges: Default::default(),
                    authorized_keys: keys(&[]),
                    clipboard_enabled: true,
                    peer_clipboard: Default::default(),
                    event_tx,
                };
                let addr = SocketAddr::new([127, 0, 0, 1].into(), 1);
                // only the header is sent: a pairing request claiming 1 GB
                // must be refused without waiting for (or allocating) it
                let (mut client, mut server) = duplex(64);
                client.write_u8(KIND_PAIR_REQUEST).await.expect("write");
                client.write_u32(1 << 30).await.expect("write");
                let result = handler
                    .handle(&mut server, "stranger".to_owned(), addr)
                    .await;
                assert!(matches!(result, Err(ControlError::TooLarge(_))));
            })
            .await;
    }

    #[tokio::test]
    async fn the_exchange_gives_both_sides_the_same_fresh_code() {
        let run = || async {
            let (mut requester, mut responder) = duplex(1024);
            let (a, b) = tokio::join!(
                requester_exchange(&mut requester, "aa", "bb"),
                responder_exchange(&mut responder, "aa", "bb"),
            );
            let (a, b) = (a.expect("requester"), b.expect("responder"));
            assert_eq!(a, b);
            assert_eq!(a.len(), 7);
            a
        };
        // fresh nonces each time: the same two devices don't get a fixed code
        let codes: std::collections::HashSet<_> = [run().await, run().await, run().await].into();
        assert!(codes.len() > 1);
    }

    #[tokio::test]
    async fn a_broken_commitment_is_detected() {
        // someone in the middle picks their nonce after seeing ours
        let (mut requester, mut fake) = duplex(1024);
        let cheat = async {
            write_frame(&mut fake, KIND_PAIR_COMMIT, &commit(&[1; NONCE_LEN])).await?;
            let _nonce_a = read_small_frame(&mut fake, KIND_PAIR_NONCE).await?;
            write_frame(&mut fake, KIND_PAIR_REVEAL, &[2; NONCE_LEN]).await?;
            Ok::<_, ControlError>(())
        };
        let (result, _) = tokio::join!(requester_exchange(&mut requester, "aa", "bb"), cheat);
        assert!(matches!(result, Err(ControlError::CommitMismatch)));
    }

    #[test]
    fn pairing_exchanges_are_rate_limited() {
        let (event_tx, _event_rx) = channel();
        let handler = Handler {
            own_fingerprint: "me".to_owned(),
            exchanges: Default::default(),
            authorized_keys: keys(&[]),
            clipboard_enabled: false,
            peer_clipboard: Default::default(),
            event_tx,
        };
        for _ in 0..MAX_EXCHANGES {
            handler.count_exchange().expect("within the limit");
        }
        // someone retrying for a matching code is stopped
        assert!(matches!(
            handler.count_exchange(),
            Err(ControlError::TooManyAttempts)
        ));
    }

    #[test]
    fn codes_depend_on_both_devices_and_both_nonces() {
        let (n1, n2) = ([1; NONCE_LEN], [2; NONCE_LEN]);
        let code = pairing_code("aa", "bb", &n1, &n2);
        assert_ne!(code, pairing_code("aa", "bc", &n1, &n2));
        assert_ne!(code, pairing_code("ab", "bb", &n1, &n2));
        assert_ne!(code, pairing_code("aa", "bb", &n2, &n2));
        assert_ne!(code, pairing_code("aa", "bb", &n1, &n1));
    }
}
