//! Clipboard follows the cursor: when the cursor enters a client, the local
//! clipboard is sent to it.
//!
//! Input events travel over the fixed-size UDP/DTLS channel, which cannot
//! carry clipboard contents. Clipboard data uses a TCP/TLS connection on the
//! same port instead. Both ends present their Lan Mouse certificate and a
//! transfer only happens if the other side's fingerprint is authorized, so
//! clipboard contents never reach a machine that was not paired.

use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    net::SocketAddr,
    process::Stdio,
    rc::Rc,
    sync::{Arc, RwLock},
    time::Duration,
};

use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    task::spawn_local,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webrtc_dtls::crypto::Certificate;

use crate::crypto;

/// Largest clipboard payload accepted or sent.
const MAX_SIZE: usize = 16 * 1024 * 1024;
/// Gives up on a peer that does not complete a transfer in time.
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub(crate) enum ClipboardError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tls(#[from] rustls::Error),
    #[error("peer {0} is not authorized")]
    Unauthorized(String),
    #[error("clipboard of {0} bytes exceeds the {MAX_SIZE} byte limit")]
    TooLarge(usize),
}

type AuthorizedKeys = Arc<RwLock<HashMap<String, String>>>;

pub(crate) struct Clipboard {
    connector: TlsConnector,
    authorized_keys: AuthorizedKeys,
    /// hash of what was last sent to each peer, to skip repeated transfers
    last_sent: Rc<RefCell<HashMap<SocketAddr, [u8; 32]>>>,
}

impl Clipboard {
    /// Start listening for clipboard transfers on TCP `port`.
    pub(crate) async fn new(
        port: u16,
        cert: &Certificate,
        authorized_keys: AuthorizedKeys,
    ) -> Result<Self, ClipboardError> {
        let (acceptor, connector) = tls(cert)?;
        let listener = TcpListener::bind(SocketAddr::new([0, 0, 0, 0].into(), port)).await?;
        spawn_local(accept_loop(listener, acceptor, authorized_keys.clone()));
        log::info!("clipboard sync listening on tcp port {port}");

        Ok(Self {
            connector,
            authorized_keys,
            last_sent: Default::default(),
        })
    }

    /// Send the local clipboard to `addr` in the background, unless that peer
    /// already received exactly this content.
    pub(crate) fn send_to(&self, addr: SocketAddr) {
        let connector = self.connector.clone();
        let authorized_keys = self.authorized_keys.clone();
        let last_sent = self.last_sent.clone();
        spawn_local(async move {
            let text = match read_clipboard().await {
                Ok(Some(text)) if !text.is_empty() => text,
                Ok(_) => return,
                Err(e) => {
                    log::warn!("could not read clipboard: {e}");
                    return;
                }
            };
            let hash: [u8; 32] = Sha256::digest(&text).into();
            if last_sent.borrow().get(&addr) == Some(&hash) {
                return;
            }
            let transfer = send(&connector, &authorized_keys, addr, &text);
            match tokio::time::timeout(TIMEOUT, transfer).await {
                Ok(Ok(())) => {
                    log::info!("sent clipboard ({} bytes) to {addr}", text.len());
                    last_sent.borrow_mut().insert(addr, hash);
                }
                Ok(Err(e)) => log::warn!("could not send clipboard to {addr}: {e}"),
                Err(_) => log::warn!("could not send clipboard to {addr}: timed out"),
            }
        });
    }
}

async fn send(
    connector: &TlsConnector,
    authorized_keys: &AuthorizedKeys,
    addr: SocketAddr,
    text: &[u8],
) -> Result<(), ClipboardError> {
    if text.len() > MAX_SIZE {
        return Err(ClipboardError::TooLarge(text.len()));
    }
    let tcp = TcpStream::connect(addr).await?;
    let mut tls = connector
        .connect(ServerName::IpAddress(addr.ip().into()), tcp)
        .await?;
    check_peer(tls.get_ref().1.peer_certificates(), authorized_keys)?;
    tls.write_u32(text.len() as u32).await?;
    tls.write_all(text).await?;
    tls.shutdown().await?;
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    authorized_keys: AuthorizedKeys,
) {
    loop {
        let (tcp, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                log::warn!("clipboard listener: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let authorized_keys = authorized_keys.clone();
        spawn_local(async move {
            let transfer = async {
                let text = receive(acceptor, &authorized_keys, tcp).await?;
                write_clipboard(&text).await?;
                Ok::<_, ClipboardError>(text.len())
            };
            match tokio::time::timeout(TIMEOUT, transfer).await {
                Ok(Ok(len)) => log::info!("received clipboard ({len} bytes) from {addr}"),
                Ok(Err(e)) => log::warn!("clipboard transfer from {addr} failed: {e}"),
                Err(_) => log::warn!("clipboard transfer from {addr} timed out"),
            }
        });
    }
}

async fn receive(
    acceptor: TlsAcceptor,
    authorized_keys: &AuthorizedKeys,
    tcp: TcpStream,
) -> Result<Vec<u8>, ClipboardError> {
    let mut tls = acceptor.accept(tcp).await?;
    check_peer(tls.get_ref().1.peer_certificates(), authorized_keys)?;
    let len = tls.read_u32().await? as usize;
    if len > MAX_SIZE {
        return Err(ClipboardError::TooLarge(len));
    }
    let mut text = vec![0; len];
    tls.read_exact(&mut text).await?;
    Ok(text)
}

fn check_peer(
    certs: Option<&[CertificateDer<'_>]>,
    authorized_keys: &AuthorizedKeys,
) -> Result<(), ClipboardError> {
    let fingerprint = certs
        .and_then(|c| c.first())
        .map(|c| crypto::generate_fingerprint(c))
        .unwrap_or_default();
    if authorized_keys
        .read()
        .expect("lock")
        .contains_key(&fingerprint)
    {
        Ok(())
    } else {
        Err(ClipboardError::Unauthorized(fingerprint))
    }
}

/// TLS server and client sides, both authenticating with `cert`.
fn tls(cert: &Certificate) -> Result<(TlsAcceptor, TlsConnector), rustls::Error> {
    let provider = Arc::new(ring::default_provider());
    let (chain, key) = identity(cert);
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

fn identity(cert: &Certificate) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let key = PrivatePkcs8KeyDer::from(cert.private_key.serialized_der.clone());
    (cert.certificate.clone(), key.into())
}

/// Accepts any certificate during the handshake (Lan Mouse certificates are
/// self-signed) while still checking the handshake signatures. Whether the
/// peer is allowed is decided afterwards by its fingerprint, see [`check_peer`].
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

#[cfg(target_os = "macos")]
const READ_CMD: &[&str] = &["/usr/bin/pbpaste"];
#[cfg(target_os = "macos")]
const WRITE_CMD: &[&str] = &["/usr/bin/pbcopy"];
#[cfg(all(unix, not(target_os = "macos")))]
const READ_CMD: &[&str] = &["wl-paste", "--no-newline", "--type", "text"];
#[cfg(all(unix, not(target_os = "macos")))]
const WRITE_CMD: &[&str] = &["wl-copy", "--type", "text/plain"];

/// The clipboard's text, or `None` if it holds no text.
#[cfg(unix)]
async fn read_clipboard() -> io::Result<Option<Vec<u8>>> {
    let output = Command::new(READ_CMD[0])
        .args(&READ_CMD[1..])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await?;
    // wl-paste fails when the clipboard is empty or holds no text
    Ok(output.status.success().then_some(output.stdout))
}

#[cfg(unix)]
async fn write_clipboard(text: &[u8]) -> io::Result<()> {
    let mut child = Command::new(WRITE_CMD[0])
        .args(&WRITE_CMD[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(text).await?;
    drop(stdin);
    // wl-copy forks to keep serving the selection; its parent exits right away
    child.wait().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn read_clipboard() -> io::Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(not(unix))]
async fn write_clipboard(_text: &[u8]) -> io::Result<()> {
    Err(io::Error::other(
        "clipboard sync is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert() -> Certificate {
        Certificate::generate_self_signed(["ignored".to_owned()]).expect("certificate")
    }

    fn authorizing(certs: &[&Certificate]) -> AuthorizedKeys {
        let keys = certs
            .iter()
            .map(|c| (crypto::certificate_fingerprint(c), "peer".to_owned()))
            .collect();
        Arc::new(RwLock::new(keys))
    }

    /// Sends `text` from a `sender` to a `receiver` over localhost.
    async fn transfer(
        sender: &Certificate,
        sender_authorizes: AuthorizedKeys,
        receiver: &Certificate,
        receiver_authorizes: AuthorizedKeys,
        text: &[u8],
    ) -> (Result<(), ClipboardError>, Result<Vec<u8>, ClipboardError>) {
        let (acceptor, _) = tls(receiver).expect("receiver tls");
        let (_, connector) = tls(sender).expect("sender tls");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let receiving = async {
            let (tcp, _) = listener.accept().await.expect("accept");
            receive(acceptor, &receiver_authorizes, tcp).await
        };
        tokio::join!(send(&connector, &sender_authorizes, addr, text), receiving)
    }

    #[tokio::test]
    async fn paired_peers_transfer_text() {
        let (a, b) = (cert(), cert());
        let (sent, received) = transfer(
            &a,
            authorizing(&[&b]),
            &b,
            authorizing(&[&a]),
            "hello ✓".as_bytes(),
        )
        .await;
        sent.expect("send");
        assert_eq!(received.expect("receive"), "hello ✓".as_bytes());
    }

    #[tokio::test]
    async fn receiver_rejects_unpaired_sender() {
        let (a, b) = (cert(), cert());
        let (_, received) = transfer(&a, authorizing(&[&b]), &b, authorizing(&[]), b"secret").await;
        assert!(matches!(received, Err(ClipboardError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn sender_refuses_unpaired_receiver() {
        let (a, b) = (cert(), cert());
        let (sent, received) =
            transfer(&a, authorizing(&[]), &b, authorizing(&[&a]), b"secret").await;
        assert!(matches!(sent, Err(ClipboardError::Unauthorized(_))));
        assert!(received.is_err(), "no clipboard may arrive: {received:?}");
    }
}
