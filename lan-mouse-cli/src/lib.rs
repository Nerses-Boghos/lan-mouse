use clap::{Args, Parser, Subcommand};
use futures::StreamExt;

use std::{io::IsTerminal, net::IpAddr, time::Duration};
use thiserror::Error;

use lan_mouse_ipc::{
    ClientHandle, ConnectionError, DiscoveredPeer, FrontendEvent, FrontendRequest, IpcError,
    PairStatus, Position, TransferState, connect_async,
};

#[derive(Debug, Error)]
pub enum CliError {
    /// is the service running?
    #[error("could not connect: `{0}` - is the service running?")]
    ServiceNotRunning(#[from] ConnectionError),
    #[error("error communicating with service: {0}")]
    Ipc(#[from] IpcError),
    #[error("{0}")]
    Failed(String),
}

#[derive(Parser, Clone, Debug, PartialEq, Eq)]
#[command(name = "lan-mouse-cli", about = "LanMouse CLI interface")]
pub struct CliArgs {
    #[command(subcommand)]
    command: CliSubcommand,
}

#[derive(Args, Clone, Debug, PartialEq, Eq)]
struct Client {
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    ips: Option<Vec<IpAddr>>,
    #[arg(long)]
    enter_hook: Option<String>,
    #[arg(long)]
    leave_hook: Option<String>,
}

#[derive(Clone, Subcommand, Debug, PartialEq, Eq)]
enum CliSubcommand {
    /// add a new client
    AddClient(Client),
    /// remove an existing client
    RemoveClient { id: ClientHandle },
    /// activate a client
    Activate { id: ClientHandle },
    /// deactivate a client
    Deactivate { id: ClientHandle },
    /// list configured clients
    List {
        /// print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// list Lan Mouse devices on the local network
    Discover {
        /// print JSON instead of text
        #[arg(long)]
        json: bool,
    },
    /// pair with a device on the local network, placing it at `pos`
    Pair {
        /// name, host name or fingerprint (prefix) of the device, see `discover`
        device: String,
        pos: Position,
    },
    /// send files and folders to a paired device (into its Downloads)
    Send {
        /// name, host name or fingerprint (prefix) of the device, see `discover`
        device: String,
        #[arg(required = true)]
        paths: Vec<std::path::PathBuf>,
    },
    /// accept a pairing request (fingerprint as shown with the request)
    PairAccept { fingerprint: String },
    /// decline a pairing request
    PairDecline { fingerprint: String },
    /// confirm that the other device shows the same code, for a pairing
    /// started here (`pair` asks by itself when run in a terminal)
    PairConfirm { fingerprint: String },
    /// cancel a pairing started here, e.g. because the codes differ
    PairCancel { fingerprint: String },
    /// print service events as JSON lines until interrupted
    Watch,
    /// change hostname
    SetHost {
        id: ClientHandle,
        host: Option<String>,
    },
    /// change port
    SetPort { id: ClientHandle, port: u16 },
    /// set position
    SetPosition { id: ClientHandle, pos: Position },
    /// set ips
    SetIps { id: ClientHandle, ips: Vec<IpAddr> },
    /// line up a client's screen: where its edge starts along ours, in pixels
    /// (e.g. its top relative to our top for a client on the left); leave
    /// out to map the edges proportionally
    SetOffset {
        id: ClientHandle,
        #[arg(allow_hyphen_values = true)]
        offset: Option<i32>,
    },
    /// place a client's screen in one go: the side it is on and, optionally,
    /// where its edge starts along ours (see set-offset); the other device
    /// follows
    Arrange {
        id: ClientHandle,
        pos: Position,
        #[arg(allow_hyphen_values = true)]
        offset: Option<i32>,
    },
    /// share the clipboard with other devices (on) or not (off)
    Clipboard {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// re-enable capture
    EnableCapture,
    /// re-enable emulation
    EnableEmulation,
    /// authorize a public key
    AuthorizeKey {
        description: String,
        sha256_fingerprint: String,
    },
    /// deauthorize a public key
    RemoveAuthorizedKey { sha256_fingerprint: String },
    /// save configuration to file
    SaveConfig,
}

pub async fn run(args: CliArgs) -> Result<(), CliError> {
    execute(args.command).await?;
    Ok(())
}

async fn execute(cmd: CliSubcommand) -> Result<(), CliError> {
    let (mut rx, mut tx) = connect_async(Some(Duration::from_millis(500))).await?;
    match cmd {
        CliSubcommand::AddClient(Client {
            hostname,
            port,
            ips,
            enter_hook,
            leave_hook,
        }) => {
            tx.request(FrontendRequest::Create).await?;
            while let Some(e) = rx.next().await {
                if let FrontendEvent::Created(handle, _, _) = e? {
                    if let Some(hostname) = hostname {
                        tx.request(FrontendRequest::UpdateHostname(handle, Some(hostname)))
                            .await?;
                    }
                    if let Some(port) = port {
                        tx.request(FrontendRequest::UpdatePort(handle, port))
                            .await?;
                    }
                    if let Some(ips) = ips {
                        tx.request(FrontendRequest::UpdateFixIps(handle, ips))
                            .await?;
                    }
                    if let Some(enter_hook) = enter_hook {
                        tx.request(FrontendRequest::UpdateEnterHook(handle, Some(enter_hook)))
                            .await?;
                    }
                    if let Some(leave_hook) = leave_hook {
                        tx.request(FrontendRequest::UpdateLeaveHook(handle, Some(leave_hook)))
                            .await?;
                    }
                    break;
                }
            }
        }
        CliSubcommand::RemoveClient { id } => tx.request(FrontendRequest::Delete(id)).await?,
        CliSubcommand::Activate { id } => tx.request(FrontendRequest::Activate(id, true)).await?,
        CliSubcommand::Deactivate { id } => {
            tx.request(FrontendRequest::Activate(id, false)).await?
        }
        CliSubcommand::List { json } => {
            tx.request(FrontendRequest::Enumerate()).await?;
            while let Some(e) = rx.next().await {
                if let FrontendEvent::Enumerate(clients) = e? {
                    if json {
                        print_json(&clients);
                        break;
                    }
                    for (handle, config, state) in clients {
                        let host = config.hostname.unwrap_or("unknown".to_owned());
                        let port = config.port;
                        let pos = config.pos;
                        let active = state.active;
                        let ips = state.ips;
                        println!(
                            "id {handle}: {host}:{port} ({pos}) active: {active}, ips: {ips:?}"
                        );
                    }
                    break;
                }
            }
        }
        CliSubcommand::SetHost { id, host } => {
            tx.request(FrontendRequest::UpdateHostname(id, host))
                .await?
        }
        CliSubcommand::SetPort { id, port } => {
            tx.request(FrontendRequest::UpdatePort(id, port)).await?
        }
        CliSubcommand::SetPosition { id, pos } => {
            tx.request(FrontendRequest::UpdatePosition(id, pos)).await?
        }
        CliSubcommand::SetIps { id, ips } => {
            tx.request(FrontendRequest::UpdateFixIps(id, ips)).await?
        }
        CliSubcommand::SetOffset { id, offset } => {
            tx.request(FrontendRequest::UpdateOffset(id, offset))
                .await?
        }
        CliSubcommand::Arrange { id, pos, offset } => {
            tx.request(FrontendRequest::Arrange {
                handle: id,
                pos,
                offset,
            })
            .await?
        }
        CliSubcommand::Clipboard { state } => {
            tx.request(FrontendRequest::SetClipboard(state == "on"))
                .await?
        }
        CliSubcommand::EnableCapture => tx.request(FrontendRequest::EnableCapture).await?,
        CliSubcommand::EnableEmulation => tx.request(FrontendRequest::EnableEmulation).await?,
        CliSubcommand::AuthorizeKey {
            description,
            sha256_fingerprint,
        } => {
            tx.request(FrontendRequest::AuthorizeKey(
                description,
                sha256_fingerprint,
            ))
            .await?
        }
        CliSubcommand::RemoveAuthorizedKey { sha256_fingerprint } => {
            tx.request(FrontendRequest::RemoveAuthorizedKey(sha256_fingerprint))
                .await?
        }
        CliSubcommand::SaveConfig => tx.request(FrontendRequest::SaveConfiguration).await?,
        CliSubcommand::Discover { json } => {
            let peers = discovered(&mut rx, &mut tx).await?;
            if json {
                print_json(&peers);
            } else if peers.is_empty() {
                println!("no devices found");
            } else {
                for p in peers {
                    let paired = if p.paired { "paired" } else { "not paired" };
                    println!(
                        "{} ({}) {paired}, fingerprint {}",
                        p.name, p.hostname, p.fingerprint
                    );
                }
            }
        }
        CliSubcommand::Pair { device, pos } => {
            let peers = discovered(&mut rx, &mut tx).await?;
            let peer = find_device(&peers, &device)?;
            let fingerprint = peer.fingerprint.clone();
            tx.request(FrontendRequest::Pair {
                fingerprint: fingerprint.clone(),
                pos,
            })
            .await?;
            while let Some(e) = rx.next().await {
                let FrontendEvent::PairUpdate {
                    fingerprint: fp,
                    name,
                    status,
                } = e?
                else {
                    continue;
                };
                if fp != fingerprint {
                    continue;
                }
                match status {
                    PairStatus::Waiting { code } => {
                        println!("{name} shows a pairing request with a code. Accept it there.");
                        let confirm = if std::io::stdin().is_terminal() {
                            ask(&format!("Does {name} show the code {code}? [y/N] ")).await
                        } else {
                            // another frontend (e.g. a bar widget) confirms
                            println!(
                                "It should show the code {code}. Confirm with: lan-mouse cli pair-confirm {fingerprint}"
                            );
                            continue;
                        };
                        tx.request(FrontendRequest::PairConfirm {
                            fingerprint: fingerprint.clone(),
                            confirm,
                        })
                        .await?;
                        if !confirm {
                            return Err(CliError::Failed(
                                "pairing cancelled: the codes must match".to_owned(),
                            ));
                        }
                        println!("Waiting for {name}...");
                    }
                    PairStatus::Paired => {
                        let place = pos.relative_phrase();
                        println!("Paired with {name}, which is now {place}.");
                        break;
                    }
                    PairStatus::Declined => {
                        return Err(CliError::Failed(format!("{name} declined the pairing")));
                    }
                    PairStatus::Failed(e) => {
                        return Err(CliError::Failed(format!("pairing with {name} failed: {e}")));
                    }
                }
            }
        }
        CliSubcommand::Send { device, paths } => {
            let peers = discovered(&mut rx, &mut tx).await?;
            let fingerprint = match find_device(&peers, &device) {
                Ok(peer) => peer.fingerprint.clone(),
                // a full fingerprint: a paired device not announced right
                // now (the service finds it by its connection)
                Err(_) if is_fingerprint(&device) => device.to_lowercase(),
                Err(e) => return Err(e),
            };
            let paths = paths
                .iter()
                .map(|p| {
                    std::path::absolute(p)
                        .map_err(|e| CliError::Failed(format!("{}: {e}", p.display())))
                })
                .collect::<Result<Vec<_>, _>>()?;
            // identifies this transfer's updates
            let id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                ^ std::process::id() as u64;
            tx.request(FrontendRequest::SendFiles {
                id,
                fingerprint,
                paths,
            })
            .await?;
            let interactive = std::io::stderr().is_terminal();
            while let Some(e) = rx.next().await {
                let FrontendEvent::Transfer(t) = e? else {
                    continue;
                };
                if t.id != id || t.incoming {
                    continue;
                }
                match t.state {
                    TransferState::Running => {
                        if interactive && t.total > 0 {
                            eprint!(
                                "\rsending {} to {}: {}%   ",
                                files_phrase(t.files),
                                t.name,
                                t.done * 100 / t.total
                            );
                        }
                    }
                    TransferState::Done { .. } => {
                        if interactive {
                            eprintln!();
                        }
                        println!(
                            "Sent {} to {} ({}).",
                            files_phrase(t.files),
                            t.name,
                            size_phrase(t.total)
                        );
                        break;
                    }
                    TransferState::Cancelled => {
                        return Err(CliError::Failed("cancelled".to_owned()));
                    }
                    TransferState::Failed(e) => {
                        if interactive {
                            eprintln!();
                        }
                        return Err(CliError::Failed(format!(
                            "sending to {} failed: {e}",
                            t.name
                        )));
                    }
                }
            }
        }
        CliSubcommand::PairAccept { fingerprint } => {
            tx.request(FrontendRequest::PairResponse {
                fingerprint,
                accept: true,
            })
            .await?
        }
        CliSubcommand::PairConfirm { fingerprint } => {
            tx.request(FrontendRequest::PairConfirm {
                fingerprint,
                confirm: true,
            })
            .await?
        }
        CliSubcommand::PairCancel { fingerprint } => {
            tx.request(FrontendRequest::PairConfirm {
                fingerprint,
                confirm: false,
            })
            .await?
        }
        CliSubcommand::PairDecline { fingerprint } => {
            tx.request(FrontendRequest::PairResponse {
                fingerprint,
                accept: false,
            })
            .await?
        }
        CliSubcommand::Watch => {
            tx.request(FrontendRequest::Sync).await?;
            tx.request(FrontendRequest::Discover).await?;
            while let Some(e) = rx.next().await {
                print_json(&e?);
            }
        }
    }
    Ok(())
}

/// A complete SHA-256 fingerprint: 32 hex bytes separated by colons.
fn is_fingerprint(text: &str) -> bool {
    let parts: Vec<_> = text.split(':').collect();
    parts.len() == 32
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn files_phrase(files: usize) -> String {
    if files == 1 {
        "1 file".to_owned()
    } else {
        format!("{files} files")
    }
}

fn size_phrase(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["bytes", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

async fn discovered(
    rx: &mut (impl futures::Stream<Item = Result<FrontendEvent, IpcError>> + Unpin),
    tx: &mut lan_mouse_ipc::AsyncFrontendRequestWriter,
) -> Result<Vec<DiscoveredPeer>, CliError> {
    tx.request(FrontendRequest::Discover).await?;
    while let Some(e) = rx.next().await {
        if let FrontendEvent::Discovered(peers) = e? {
            return Ok(peers);
        }
    }
    Ok(vec![])
}

/// Match `query` against names, host names and fingerprint prefixes.
fn find_device<'a>(
    peers: &'a [DiscoveredPeer],
    query: &str,
) -> Result<&'a DiscoveredPeer, CliError> {
    let query = query.trim_end_matches('.');
    let matches: Vec<_> = peers
        .iter()
        .filter(|p| {
            p.name.eq_ignore_ascii_case(query)
                || p.hostname.eq_ignore_ascii_case(query)
                || p.hostname
                    .strip_suffix(".local")
                    .is_some_and(|h| h.eq_ignore_ascii_case(query))
                || (query.len() >= 5 && p.fingerprint.starts_with(&query.to_lowercase()))
        })
        .collect();
    match matches[..] {
        [peer] => Ok(peer),
        [] => Err(CliError::Failed(format!(
            "no device \"{query}\" on the network, see `lan-mouse cli discover`"
        ))),
        _ => Err(CliError::Failed(format!(
            "\"{query}\" matches several devices, use the fingerprint"
        ))),
    }
}

/// Asks a yes/no question on the terminal; anything but "y"/"yes" is no.
async fn ask(question: &str) -> bool {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(question.as_bytes()).await;
    let _ = stdout.flush().await;
    let mut line = String::new();
    let _ = BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await;
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn print_json(value: &impl serde::Serialize) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("could not encode as JSON: {e}"),
    }
}
