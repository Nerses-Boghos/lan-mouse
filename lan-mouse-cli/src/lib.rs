use clap::{Args, Parser, Subcommand};
use futures::StreamExt;

use std::{net::IpAddr, time::Duration};
use thiserror::Error;

use lan_mouse_ipc::{
    ClientHandle, ConnectionError, DiscoveredPeer, FrontendEvent, FrontendRequest, IpcError,
    PairStatus, Position, connect_async,
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
    /// accept a pairing request (fingerprint as shown with the request)
    PairAccept { fingerprint: String },
    /// decline a pairing request
    PairDecline { fingerprint: String },
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
                        println!("Confirm the pairing on {name}. It should show the code {code}.")
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
        CliSubcommand::PairAccept { fingerprint } => {
            tx.request(FrontendRequest::PairResponse {
                fingerprint,
                accept: true,
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

fn print_json(value: &impl serde::Serialize) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("could not encode as JSON: {e}"),
    }
}
