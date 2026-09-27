//! Control channel between Lan Mouse devices, for everything that doesn't fit
//! the fixed-size UDP/DTLS input protocol: clipboard contents and pairing.
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
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, RwLock},
    time::Duration,
};

use lan_mouse_ipc::Position;
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
    task::spawn_local,
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
/// How long a pairing request waits for the user to answer it.
pub(crate) const PAIR_TIMEOUT: Duration = Duration::from_secs(120);

const KIND_CLIPBOARD: u8 = 1;
const KIND_PAIR_REQUEST: u8 = 2;
const KIND_PAIR_REPLY: u8 = 3;

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

pub(crate) enum ControlEvent {
    /// A device asks to pair. Answer through `reply`; dropping it declines.
    PairRequest {
        fingerprint: String,
        request: PairRequest,
        reply: oneshot::Sender<PairReply>,
    },
    /// A pairing started with [`Control::pair`] completed.
    PairFinished {
        fingerprint: String,
        /// where the other device sits relative to this one
        pos: Position,
        result: Result<PairReply, ControlError>,
    },
}

type AuthorizedKeys = Arc<RwLock<HashMap<String, String>>>;

pub(crate) struct Control {
    /// the TCP port listened on (only read by tests, which bind port 0)
    #[cfg_attr(not(test), allow(dead_code))]
    port: u16,
    connector: TlsConnector,
    authorized_keys: AuthorizedKeys,
    clipboard_enabled: bool,
    /// hash of the clipboard each peer (by ip) is known to have
    peer_clipboard: Rc<RefCell<HashMap<std::net::IpAddr, [u8; 32]>>>,
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
        let handler = Handler {
            authorized_keys: authorized_keys.clone(),
            clipboard_enabled,
            peer_clipboard: peer_clipboard.clone(),
            event_tx: event_tx.clone(),
        };
        spawn_local(accept_loop(listener, acceptor, handler));
        log::info!("control channel listening on tcp port {port}");

        Ok(Self {
            port,
            connector,
            authorized_keys,
            clipboard_enabled,
            peer_clipboard,
            event_tx,
            event_rx,
        })
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
            if peer_clipboard.borrow().get(&addr.ip()) == Some(&hash) {
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
                    peer_clipboard.borrow_mut().insert(addr.ip(), hash);
                }
                Err(e) => log::warn!("could not send clipboard to {addr}: {e}"),
            }
        });
    }

    /// Ask the device at `addr`, whose certificate must match `fingerprint`,
    /// to pair; it will sit at `pos` relative to this one. The outcome arrives
    /// as [`ControlEvent::PairFinished`].
    pub(crate) fn pair(
        &self,
        addr: SocketAddr,
        fingerprint: String,
        pos: Position,
        request: PairRequest,
    ) {
        let connector = self.connector.clone();
        let event_tx = self.event_tx.clone();
        spawn_local(async move {
            let result = timeout(PAIR_TIMEOUT + TIMEOUT, async {
                let (mut tls, presented) = connect(&connector, addr).await?;
                // The advertised fingerprint is what the user picked; make
                // sure the device answering really holds that certificate.
                if presented != fingerprint {
                    return Err(ControlError::WrongPeer(presented));
                }
                write_frame(&mut tls, KIND_PAIR_REQUEST, &serde_json::to_vec(&request)?).await?;
                let payload = read_frame(&mut tls, KIND_PAIR_REPLY).await?;
                Ok(serde_json::from_slice::<PairReply>(&payload)?)
            })
            .await;
            let _ = event_tx.send(ControlEvent::PairFinished {
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
    authorized_keys: AuthorizedKeys,
    clipboard_enabled: bool,
    peer_clipboard: Rc<RefCell<HashMap<std::net::IpAddr, [u8; 32]>>>,
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
            KIND_CLIPBOARD if !paired => return Err(ControlError::Unauthorized(fingerprint)),
            KIND_CLIPBOARD | KIND_PAIR_REQUEST => {}
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
                    .insert(addr.ip(), digest(&payload));
                log::info!("received clipboard ({} bytes) from {addr}", payload.len());
                Ok(())
            }
            KIND_PAIR_REQUEST => {
                let request: PairRequest = serde_json::from_slice(&payload)?;
                log::info!("{} ({addr}) asks to pair", request.name);
                let (reply_tx, reply_rx) = oneshot::channel();
                let _ = self.event_tx.send(ControlEvent::PairRequest {
                    fingerprint,
                    request,
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
                tls.shutdown().await?;
                Ok(())
            }
            kind => Err(ControlError::UnexpectedKind(kind)),
        }
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

/// Short code both devices show while pairing. Matching codes mean each side
/// talks to the certificate the other one holds (no one in between).
pub(crate) fn pairing_code(a: &str, b: &str) -> String {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let hash = Sha256::digest(format!("lan-mouse pairing\n{first}\n{second}"));
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

    /// `a` asks `b` to pair, expecting `b`'s certificate unless `impostor`
    /// (then `b` is not who `a` meant). `b` answers with `accept`, or drops
    /// the request if `None`. Returns what `a` learns.
    async fn pair(impostor: bool, accept: Option<bool>) -> Result<PairReply, ControlError> {
        let (a_cert, b_cert) = (cert(), cert());
        let mut a = Control::new(0, &a_cert, keys(&[]), false).await.expect("a");
        let mut b = Control::new(0, &b_cert, keys(&[]), false).await.expect("b");
        let b_addr = SocketAddr::new([127, 0, 0, 1].into(), b.port());
        let expected = if impostor { cert() } else { b_cert.clone() };
        a.pair(
            b_addr,
            crypto::certificate_fingerprint(&expected),
            Position::Right,
            request(),
        );

        let answer = async {
            let ControlEvent::PairRequest {
                fingerprint,
                request: received,
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
        };
        if !impostor {
            answer.await;
        }
        let ControlEvent::PairFinished { result, pos, .. } = a.event().await else {
            panic!("expected the pairing to finish");
        };
        assert_eq!(pos, Position::Right);
        result
    }

    async fn pair_with_receiver(accept: Option<bool>) -> Result<PairReply, ControlError> {
        pair(false, accept).await
    }

    #[tokio::test]
    async fn pairing_is_accepted() {
        LocalSet::new()
            .run_until(async {
                let reply = pair_with_receiver(Some(true)).await.expect("reply");
                assert!(reply.accepted);
                assert_eq!(reply.hostname, "receiver.local");
            })
            .await;
    }

    #[tokio::test]
    async fn pairing_is_declined() {
        LocalSet::new()
            .run_until(async {
                assert!(
                    !pair_with_receiver(Some(false))
                        .await
                        .expect("reply")
                        .accepted
                );
                // dropping the request without an answer declines too
                assert!(!pair_with_receiver(None).await.expect("reply").accepted);
            })
            .await;
    }

    #[tokio::test]
    async fn pairing_refuses_an_impostor() {
        LocalSet::new()
            .run_until(async {
                let result = pair(true, Some(true)).await;
                assert!(matches!(result, Err(ControlError::WrongPeer(_))));
            })
            .await;
    }

    #[tokio::test]
    async fn unpaired_devices_cannot_send_the_clipboard() {
        LocalSet::new()
            .run_until(async {
                let (event_tx, _event_rx) = channel();
                let handler = Handler {
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

    #[test]
    fn pairing_codes_match_on_both_sides() {
        let code = pairing_code("aa:bb", "cc:dd");
        assert_eq!(code, pairing_code("cc:dd", "aa:bb"));
        assert_eq!(code.len(), 7);
        assert_ne!(code, pairing_code("aa:bb", "cc:de"));
    }
}
