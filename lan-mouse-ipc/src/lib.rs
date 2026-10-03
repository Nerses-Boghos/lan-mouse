use std::{
    collections::{HashMap, HashSet},
    env::VarError,
    fmt::Display,
    io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
};
use thiserror::Error;

#[cfg(unix)]
use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

mod connect;
mod connect_async;
mod listen;

pub use connect::{FrontendEventReader, FrontendRequestWriter, connect, try_connect};
pub use connect_async::{AsyncFrontendEventReader, AsyncFrontendRequestWriter, connect_async};
pub use listen::AsyncFrontendListener;

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error(transparent)]
    SocketPath(#[from] SocketPathError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("connection timed out")]
    Timeout,
}

#[derive(Debug, Error)]
pub enum IpcListenerCreationError {
    #[error("could not determine socket-path: `{0}`")]
    SocketPath(#[from] SocketPathError),
    #[error("service already running!")]
    AlreadyRunning,
    #[error("failed to bind lan-mouse socket: `{0}`")]
    Bind(io::Error),
}

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("io error occured: `{0}`")]
    Io(#[from] io::Error),
    #[error("invalid json: `{0}`")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Listen(#[from] IpcListenerCreationError),
}

pub const DEFAULT_PORT: u16 = 4242;

#[derive(Debug, Default, Eq, Hash, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Position {
    #[default]
    Left,
    Right,
    Top,
    Bottom,
}

impl Position {
    /// Where something at this position is, from the user's point of view:
    /// "on your left", "above", ...
    pub fn relative_phrase(&self) -> &'static str {
        match self {
            Position::Left => "on your left",
            Position::Right => "on your right",
            Position::Top => "above",
            Position::Bottom => "below",
        }
    }

    pub fn opposite(&self) -> Self {
        match self {
            Position::Left => Position::Right,
            Position::Right => Position::Left,
            Position::Top => Position::Bottom,
            Position::Bottom => Position::Top,
        }
    }
}

#[derive(Debug, Error)]
#[error("not a valid position: {pos}")]
pub struct PositionParseError {
    pos: String,
}

impl FromStr for Position {
    type Err = PositionParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "top" => Ok(Self::Top),
            "bottom" => Ok(Self::Bottom),
            _ => Err(PositionParseError { pos: s.into() }),
        }
    }
}

impl Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Position::Left => "left",
                Position::Right => "right",
                Position::Top => "top",
                Position::Bottom => "bottom",
            }
        )
    }
}

impl TryFrom<&str> for Position {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "left" => Ok(Position::Left),
            "right" => Ok(Position::Right),
            "top" => Ok(Position::Top),
            "bottom" => Ok(Position::Bottom),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// hostname of this client
    pub hostname: Option<String>,
    /// fix ips, determined by the user
    pub fix_ips: Vec<IpAddr>,
    /// both active_addr and addrs can be None / empty so port needs to be stored seperately
    pub port: u16,
    /// position of a client on screen
    pub pos: Position,
    /// enter hook
    pub cmd: Option<String>,
    /// leave hook
    pub leave_cmd: Option<String>,
    /// Where the client's screen starts along the shared edge, in this
    /// device's logical pixels (e.g. its top relative to this screen's top
    /// for a client on the left). `None` maps the edges proportionally.
    #[serde(default)]
    pub offset: Option<i32>,
    /// The client's certificate fingerprint, once paired: identifies it on
    /// the control channel (host names and addresses change).
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// When `pos` and `offset` were last changed (milliseconds since the
    /// Unix epoch), on either device: the newer arrangement wins when the
    /// two devices exchange theirs.
    #[serde(default)]
    pub arranged_at: Option<u64>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            hostname: Default::default(),
            fix_ips: Default::default(),
            pos: Default::default(),
            cmd: None,
            leave_cmd: None,
            offset: None,
            fingerprint: None,
            arranged_at: None,
        }
    }
}

pub type ClientHandle = u64;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClientState {
    /// events should be sent to and received from the client
    pub active: bool,
    /// `active` address of the client, used to send data to.
    /// This should generally be the socket address where data
    /// was last received from.
    pub active_addr: Option<SocketAddr>,
    /// tracks whether or not the client is available for emulation
    pub alive: bool,
    /// ips from dns
    pub dns_ips: Vec<IpAddr>,
    /// all ip addresses associated with a particular client
    /// e.g. Laptops usually have at least an ethernet and a wifi port
    /// which have different ip addresses
    pub ips: HashSet<IpAddr>,
    /// client has pressed keys
    pub has_pressed_keys: bool,
    /// dns resolving in progress
    pub resolving: bool,
    /// Peer's build short commit hash from the [`Hello`] proto
    /// event. `None` means we haven't received a Hello yet — either
    /// the connection is fresh, or the peer is on an older build
    /// that predates the Hello event. The frontend uses this to
    /// soft-warn on version mismatch.
    pub peer_commit: Option<[u8; 8]>,
    /// the client's desktop size in logical pixels, as it reported it
    #[serde(default)]
    pub peer_size: Option<(u32, u32)>,
    /// the client's monitors in its own logical coordinates, as it reported
    /// them (for drawing the arrangement)
    #[serde(default)]
    pub peer_monitors: Vec<Monitor>,
    /// the last connection attempt was refused: the client doesn't trust
    /// this device (anymore) and has to pair again
    #[serde(default)]
    pub refused: bool,
}

/// Sending or receiving files: how far along, or how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferUpdate {
    pub id: u64,
    /// the other device
    pub fingerprint: String,
    pub name: String,
    /// receiving (true) or sending
    pub incoming: bool,
    /// carried by a drag: kept only if it ends in a drop on the receiver
    #[serde(default)]
    pub dragged: bool,
    pub files: usize,
    /// bytes so far, of `total`
    pub done: u64,
    pub total: u64,
    pub state: TransferState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferState {
    Running,
    /// where the received items were saved (empty when sending)
    Done {
        saved: Vec<std::path::PathBuf>,
    },
    Failed(String),
    /// a drag taken back before it was dropped
    Cancelled,
}

/// A monitor's area in its device's logical pixels.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Monitor {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrontendEvent {
    /// a client was created
    Created(ClientHandle, ClientConfig, ClientState),
    /// no such client
    NoSuchClient(ClientHandle),
    /// state changed
    State(ClientHandle, ClientConfig, ClientState),
    /// the client was deleted
    Deleted(ClientHandle),
    /// new port, reason of failure (if failed)
    PortChanged(u16, Option<String>),
    /// list of all clients, used for initial state synchronization
    Enumerate(Vec<(ClientHandle, ClientConfig, ClientState)>),
    /// an error occured
    Error(String),
    /// capture status
    CaptureStatus(Status),
    /// emulation status
    EmulationStatus(Status),
    /// authorized public key fingerprints have been updated
    AuthorizedUpdated(HashMap<String, String>),
    /// public key fingerprint of this device
    PublicKeyFingerprint(String),
    /// new device connected
    DeviceConnected {
        addr: SocketAddr,
        fingerprint: String,
    },
    /// incoming device entered the screen
    DeviceEntered {
        fingerprint: String,
        addr: SocketAddr,
        pos: Position,
    },
    /// incoming disconnected
    IncomingDisconnected(SocketAddr),
    /// failed connection attempt (approval for fingerprint required)
    ConnectionAttempt { fingerprint: String },
    /// Lan Mouse devices currently visible on the local network
    Discovered(Vec<DiscoveredPeer>),
    /// the keyboard and mouse control this client now (`None`: this device)
    Controlling(Option<ClientHandle>),
    /// progress or outcome of sending or receiving files
    Transfer(TransferUpdate),
    /// whether the clipboard follows the cursor to other devices
    ClipboardStatus(bool),
    /// a device asks to pair; answer with [`FrontendRequest::PairResponse`].
    /// `pos` is where the requesting device will be relative to this one.
    PairRequest {
        fingerprint: String,
        name: String,
        code: String,
        pos: Position,
    },
    /// progress of a pairing, started from either side
    PairUpdate {
        fingerprint: String,
        name: String,
        status: PairStatus,
    },
}

/// A Lan Mouse device announced on the local network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    /// sha256 certificate fingerprint, the device's identity
    pub fingerprint: String,
    /// display name, usually the device's host name
    pub name: String,
    /// resolvable host name, e.g. `macbook.local`
    pub hostname: String,
    pub ips: Vec<IpAddr>,
    pub port: u16,
    /// whether this device's fingerprint is already authorized
    pub paired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairStatus {
    /// request sent, waiting for the other device; both show this code
    Waiting {
        code: String,
    },
    Paired,
    Declined,
    Failed(String),
}

#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum FrontendRequest {
    /// activate/deactivate client
    Activate(ClientHandle, bool),
    /// add a new client
    Create,
    /// change the listen port (recreate udp listener)
    ChangePort(u16),
    /// remove a client
    Delete(ClientHandle),
    /// request an enumeration of all clients
    Enumerate(),
    /// resolve dns
    ResolveDns(ClientHandle),
    /// update hostname
    UpdateHostname(ClientHandle, Option<String>),
    /// update port
    UpdatePort(ClientHandle, u16),
    /// update position
    UpdatePosition(ClientHandle, Position),
    /// update fix-ips
    UpdateFixIps(ClientHandle, Vec<IpAddr>),
    /// request reenabling input capture
    EnableCapture,
    /// request reenabling input emulation
    EnableEmulation,
    /// synchronize all state
    Sync,
    /// authorize fingerprint (description, fingerprint)
    AuthorizeKey(String, String),
    /// remove fingerprint (fingerprint)
    RemoveAuthorizedKey(String),
    /// change the hook command
    UpdateEnterHook(u64, Option<String>),
    /// change the leave hook command
    UpdateLeaveHook(u64, Option<String>),
    /// save config file
    SaveConfiguration,
    /// set where the client's screen starts along the shared edge, see
    /// [`ClientConfig::offset`]
    UpdateOffset(ClientHandle, Option<i32>),
    /// place the client at `pos`, its screen starting `offset` along the
    /// shared edge (see [`ClientConfig::offset`]); both devices follow
    Arrange {
        handle: ClientHandle,
        pos: Position,
        offset: Option<i32>,
    },
    /// request the list of discovered devices
    Discover,
    /// share the clipboard with other devices, or stop
    SetClipboard(bool),
    /// send files and folders (absolute paths) to the paired device with
    /// this fingerprint; `id` identifies the transfer in its updates
    SendFiles {
        id: u64,
        fingerprint: String,
        paths: Vec<std::path::PathBuf>,
    },
    /// pair with a discovered device that will sit at `pos` relative to this one
    Pair { fingerprint: String, pos: Position },
    /// accept or decline a [`FrontendEvent::PairRequest`]
    PairResponse { fingerprint: String, accept: bool },
    /// confirm (or reject) that the other device shows the same code, for a
    /// pairing this device started; see [`PairStatus::Waiting`]
    PairConfirm { fingerprint: String, confirm: bool },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Status {
    #[default]
    Disabled,
    Enabled,
}

impl From<Status> for bool {
    fn from(status: Status) -> Self {
        match status {
            Status::Enabled => true,
            Status::Disabled => false,
        }
    }
}

#[cfg(unix)]
const LAN_MOUSE_SOCKET_NAME: &str = "lan-mouse-socket.sock";

#[derive(Debug, Error)]
pub enum SocketPathError {
    #[error("could not determine $XDG_RUNTIME_DIR: `{0}`")]
    XdgRuntimeDirNotFound(VarError),
    #[error("could not determine $HOME: `{0}`")]
    HomeDirNotFound(VarError),
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn default_socket_path() -> Result<PathBuf, SocketPathError> {
    let xdg_runtime_dir =
        env::var("XDG_RUNTIME_DIR").map_err(SocketPathError::XdgRuntimeDirNotFound)?;
    Ok(Path::new(xdg_runtime_dir.as_str()).join(LAN_MOUSE_SOCKET_NAME))
}

#[cfg(all(unix, target_os = "macos"))]
pub fn default_socket_path() -> Result<PathBuf, SocketPathError> {
    let home = env::var("HOME").map_err(SocketPathError::HomeDirNotFound)?;
    Ok(Path::new(home.as_str())
        .join("Library")
        .join("Caches")
        .join(LAN_MOUSE_SOCKET_NAME))
}

/// Check if a lan-mouse service is already running by probing the IPC socket.
#[cfg(unix)]
pub fn is_service_running() -> bool {
    let Ok(socket_path) = default_socket_path() else {
        return false;
    };
    std::os::unix::net::UnixStream::connect(socket_path).is_ok()
}

/// Check if a lan-mouse service is already running by probing the IPC socket.
#[cfg(windows)]
pub fn is_service_running() -> bool {
    std::net::TcpStream::connect("127.0.0.1:5252").is_ok()
}
