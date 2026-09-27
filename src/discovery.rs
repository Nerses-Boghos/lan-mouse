//! Finds other Lan Mouse devices on the local network, and announces this one.
//!
//! Every device advertises a `_lan-mouse._udp` DNS-SD service over mDNS whose
//! TXT record carries its certificate fingerprint. The fingerprint is only a
//! hint for finding a device: pairing verifies it against the certificate
//! presented over TLS.

use std::{collections::HashMap, net::IpAddr};

use lan_mouse_ipc::DiscoveredPeer;
use mdns_sd::{IfKind, Receiver, ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE_TYPE: &str = "_lan-mouse._udp.local.";
/// Bump when the pairing / control protocol changes incompatibly.
const PROTOCOL_VERSION: &str = "2";

pub(crate) struct Discovery {
    daemon: ServiceDaemon,
    events: Receiver<ServiceEvent>,
    /// what this device announces as, to announce it again (port change)
    name: String,
    host: String,
    /// the registered announcement's full name
    announced: String,
    own_fingerprint: String,
    /// discovered devices by their mDNS full name
    peers: HashMap<String, DiscoveredPeer>,
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
        let host = format!("{hostname}.");
        let info = announcement(name, &host, port, fingerprint)?;
        let announced = info.get_fullname().to_owned();
        daemon.register(info)?;
        let events = daemon.browse(SERVICE_TYPE)?;
        log::info!("announcing this device as \"{name}\" ({host})");
        Ok(Self {
            daemon,
            events,
            name: name.to_owned(),
            host,
            announced,
            own_fingerprint: fingerprint.to_owned(),
            peers: HashMap::new(),
        })
    }

    /// Waits until the set of discovered devices changes.
    pub(crate) async fn changed(&mut self) {
        loop {
            let Ok(event) = self.events.recv_async().await else {
                // daemon gone: never report changes again
                return std::future::pending().await;
            };
            if self.apply(event) {
                return;
            }
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

    /// Announce this device at another port.
    pub(crate) fn set_port(&mut self, port: u16) {
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
                let peer = DiscoveredPeer {
                    fingerprint: fingerprint.to_owned(),
                    name: unescape(name),
                    hostname: info.get_hostname().trim_end_matches('.').to_owned(),
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
                }
                removed.is_some()
            }
            _ => false,
        }
    }
}

/// The DNS-SD record announcing this device.
fn announcement(
    name: &str,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<ServiceInfo, mdns_sd::Error> {
    let properties = [("fp", fingerprint), ("v", PROTOCOL_VERSION)];
    Ok(ServiceInfo::new(SERVICE_TYPE, name, host, "", port, &properties[..])?.enable_addr_auto())
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
    fn instance_names_are_unescaped() {
        assert_eq!(unescape(r"My\032Mac"), "My Mac");
        assert_eq!(unescape(r"a\.b"), "a.b");
        assert_eq!(unescape("plain"), "plain");
    }
}
