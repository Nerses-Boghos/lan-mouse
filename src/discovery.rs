//! Finds other Lan Mouse devices on the local network, and announces this one.
//!
//! Every device advertises a `_lan-mouse._udp` DNS-SD service over mDNS whose
//! TXT record carries its certificate fingerprint. The fingerprint is only a
//! hint for finding a device: pairing verifies it against the certificate
//! presented over TLS.
//!
//! The service points at a host name of its own (`lan-mouse-<id>.local`),
//! never at the machine's: that one belongs to the system's mDNS responder
//! (Bonjour, Avahi), and answering for it too looks like a second machine
//! with the same name, so macOS renames itself ("Name-2.local"). The
//! machine's name travels in the TXT record (`host`).

use std::{collections::HashMap, net::IpAddr, pin::Pin, time::Duration};

use lan_mouse_ipc::DiscoveredPeer;
use tokio::time::Sleep;

use mdns_sd::{DaemonEvent, IfKind, Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE_TYPE: &str = "_lan-mouse._udp.local.";
/// Bump when the pairing / control protocol changes incompatibly.
const PROTOCOL_VERSION: &str = "4";

pub(crate) struct Discovery {
    daemon: ServiceDaemon,
    events: Receiver<ServiceEvent>,
    /// the daemon's own events: new addresses mean another network
    monitor: Receiver<DaemonEvent>,
    port: u16,
    /// what this device announces as, to announce it again (port change)
    name: String,
    host: String,
    /// the registered announcement's full name
    announced: String,
    own_fingerprint: String,
    /// discovered devices by their mDNS full name
    peers: HashMap<String, DiscoveredPeer>,
    /// when to look around again, see [`Discovery::changed`]
    look_again: Option<Pin<Box<Sleep>>>,
}

impl Discovery {
    /// Announce this device as `name`, reachable at `hostname`:`port`.
    pub(crate) fn new(
        name: &str,
        hostname: &str,
        port: u16,
        fingerprint: &str,
    ) -> Result<Self, mdns_sd::Error> {
        let daemon = ServiceDaemon::new()?;
        // Loopback addresses would lead other devices back to themselves.
        daemon.disable_interface(vec![IfKind::LoopbackV4, IfKind::LoopbackV6])?;
        let host = hostname.to_owned();
        let info = announcement(name, &host, port, fingerprint)?;
        let announced = info.get_fullname().to_owned();
        daemon.register(info)?;
        let events = daemon.browse(SERVICE_TYPE)?;
        let monitor = daemon.monitor()?;
        log::info!("announcing this device as \"{name}\" ({host})");
        Ok(Self {
            daemon,
            events,
            monitor,
            port,
            name: name.to_owned(),
            host,
            announced,
            own_fingerprint: fingerprint.to_owned(),
            peers: HashMap::new(),
            look_again: None,
        })
    }

    /// Waits until the set of discovered devices changes.
    pub(crate) async fn changed(&mut self) {
        loop {
            tokio::select! {
                event = self.events.recv_async() => {
                    let Ok(event) = event else {
                        // daemon gone: never report changes again
                        return std::future::pending().await;
                    };
                    if self.apply(event) {
                        return;
                    }
                }
                // A device that stops answering the cache's refresh queries
                // counts as gone, though some (a Mac after waking up) still
                // answer a fresh search: search again to be sure.
                _ = async { self.look_again.as_mut().unwrap().await }, if self.look_again.is_some() => {
                    self.look_again = None;
                    self.browse_again();
                }
                Ok(DaemonEvent::IpAdd(ip)) = self.monitor.recv_async() => {
                    if !(ip.is_loopback() || is_link_local(&ip)) {
                        self.network_changed(ip);
                    }
                }
            }
        }
    }

    /// This device got a new address (joined a network): announce it there
    /// right away and look for devices again, instead of waiting for the
    /// next scheduled query, which can be many minutes away.
    fn network_changed(&mut self, ip: IpAddr) {
        log::info!("new network address {ip}: announcing and looking around again");
        self.set_port(self.port);
        self.browse_again();
    }

    fn browse_again(&mut self) {
        let _ = self.daemon.stop_browse(SERVICE_TYPE);
        match self.daemon.browse(SERVICE_TYPE) {
            Ok(events) => self.events = events,
            Err(e) => log::warn!("could not look for devices: {e}"),
        }
    }

    /// Discovered devices, `paired` resolved by `is_paired`.
    pub(crate) fn peers(&self, is_paired: impl Fn(&str) -> bool) -> Vec<DiscoveredPeer> {
        let mut peers: Vec<_> = self
            .peers
            .values()
            .cloned()
            .map(|mut p| {
                p.paired = is_paired(&p.fingerprint);
                p
            })
            .collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name));
        peers
    }

    pub(crate) fn get(&self, fingerprint: &str) -> Option<DiscoveredPeer> {
        self.peers
            .values()
            .find(|p| p.fingerprint == fingerprint)
            .cloned()
    }

    /// Announce this device at another port (or again at the same one).
    pub(crate) fn set_port(&mut self, port: u16) {
        self.port = port;
        let _ = self.daemon.unregister(&self.announced);
        let registered = announcement(&self.name, &self.host, port, &self.own_fingerprint)
            .and_then(|info| {
                let fullname = info.get_fullname().to_owned();
                self.daemon.register(info).map(|()| fullname)
            });
        match registered {
            Ok(fullname) => self.announced = fullname,
            Err(e) => log::warn!("could not announce this device at port {port}: {e}"),
        }
    }

    pub(crate) fn terminate(&self) {
        let _ = self.daemon.shutdown();
    }

    /// Returns whether the set of devices changed.
    fn apply(&mut self, event: ServiceEvent) -> bool {
        match event {
            ServiceEvent::ServiceResolved(info) => {
                let Some(fingerprint) = info.get_property_val_str("fp") else {
                    return false;
                };
                if fingerprint == self.own_fingerprint {
                    return false;
                }
                // Pairing changed incompatibly between versions: an older
                // device would only end up paired on one side.
                let version = info.get_property_val_str("v").unwrap_or("");
                if version != PROTOCOL_VERSION {
                    log::info!(
                        "ignoring {} (protocol version {version:?}, this device speaks {PROTOCOL_VERSION}): update it",
                        info.get_fullname()
                    );
                    return false;
                }
                let fullname = info.get_fullname();
                let name = fullname
                    .strip_suffix(SERVICE_TYPE)
                    .and_then(|n| n.strip_suffix('.'))
                    .unwrap_or(fullname);
                let mut ips: Vec<IpAddr> = info
                    .get_addresses_v4()
                    .into_iter()
                    .filter(|ip| !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()))
                    .map(IpAddr::V4)
                    .collect();
                ips.sort();
                // the machine's own name; older versions announced it directly
                let hostname = info
                    .get_property_val_str("host")
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| info.get_hostname())
                    .trim_end_matches('.')
                    .to_owned();
                // older versions only had the (possibly renamed) instance name
                let name = info
                    .get_property_val_str("name")
                    .filter(|n| !n.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| unescape(name));
                let peer = DiscoveredPeer {
                    fingerprint: fingerprint.to_owned(),
                    name,
                    hostname,
                    ips,
                    port: info.get_port(),
                    paired: false,
                };
                let changed = self.peers.get(fullname) != Some(&peer);
                if changed {
                    log::info!("discovered {} ({})", peer.name, peer.hostname);
                }
                self.peers.insert(fullname.to_owned(), peer);
                changed
            }
            ServiceEvent::ServiceRemoved(_, fullname) => {
                let removed = self.peers.remove(&fullname);
                if let Some(peer) = &removed {
                    log::info!("{} left the network", peer.name);
                    self.look_again = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
                }
                removed.is_some()
            }
            _ => false,
        }
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// The DNS-SD record announcing this device, reachable at the machine's
/// `.local` name `host`.
fn announcement(
    name: &str,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<ServiceInfo, mdns_sd::Error> {
    let properties = [
        ("fp", fingerprint),
        ("v", PROTOCOL_VERSION),
        ("host", host),
        ("name", name),
    ];
    let label = announced_host_label(fingerprint);
    let own_host = format!("{label}.local.");
    // Unique per device, so never in conflict with another one: with
    // probing, this device's own announcement still cached on the network
    // (from before a restart) counted as a conflict, and the name grew a
    // " (2)", " (3)", ... each time. The name shown is the one in the TXT
    // record.
    let instance = format!("{name} {label}");
    let mut info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &own_host,
        "",
        port,
        &properties[..],
    )?
    .enable_addr_auto();
    info.set_requires_probe(false);
    Ok(info)
}

/// The host label this device's service points at: unique per device (its
/// certificate) and never the machine's own name, see the module docs.
fn announced_host_label(fingerprint: &str) -> String {
    let id: String = fingerprint
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    format!("lan-mouse-{}", id.to_ascii_lowercase())
}

/// This machine's host name, without a `.local` suffix.
pub(crate) fn local_name() -> String {
    let name = os_host_name();
    let name = name.trim_end_matches(".local").trim();
    if name.is_empty() {
        "lan-mouse".to_owned()
    } else {
        name.to_owned()
    }
}

#[cfg(unix)]
fn os_host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
    // on success (truncation is fine for a display name).
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(not(unix))]
fn os_host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// The `.local` host name this machine is reachable under (answered by the
/// system's mDNS responder, Avahi or Bonjour).
pub(crate) fn local_hostname() -> String {
    format!("{}.local", local_host_label(&local_name()))
}

/// A host name label usable under `.local`: letters, digits and dashes.
fn local_host_label(name: &str) -> String {
    let label: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    label.trim_matches('-').to_owned()
}

/// Undo DNS-SD escaping of instance names (`\.`, `\032`, ...).
fn unescape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let digits: String = chars.clone().take(3).collect();
        if digits.len() == 3 && digits.chars().all(|d| d.is_ascii_digit()) {
            if let Ok(code) = digits.parse::<u8>() {
                out.push(code as char);
                chars.nth(2);
                continue;
            }
        }
        if let Some(next) = chars.next() {
            out.push(next);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_labels_are_dns_safe() {
        assert_eq!(local_host_label("Nerses-MacBook-Air"), "Nerses-MacBook-Air");
        assert_eq!(local_host_label("My Mac (2)"), "My-Mac--2");
    }

    #[test]
    fn the_service_never_claims_the_machines_name() {
        let label = announced_host_label("40:4C:74:fe:46:e1");
        assert_eq!(label, "lan-mouse-404c74fe");
        let info = announcement("Mac", "Nerses-MacBook-Air.local", 4242, "40:4c:74:fe:46:e1")
            .expect("announcement");
        assert_eq!(info.get_hostname(), "lan-mouse-404c74fe.local.");
        assert_eq!(
            info.get_property_val_str("host"),
            Some("Nerses-MacBook-Air.local")
        );
        // shown as is, and never renamed over a conflict
        assert_eq!(info.get_property_val_str("name"), Some("Mac"));
        assert!(!info.requires_probe());
    }

    #[test]
    fn instance_names_are_unescaped() {
        assert_eq!(unescape(r"My\032Mac"), "My Mac");
        assert_eq!(unescape(r"a\.b"), "a.b");
        assert_eq!(unescape("plain"), "plain");
    }
}
