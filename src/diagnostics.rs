//! What a problem report is made of: this device's recent log, which a
//! paired device can also ask for over their connection, so a report made
//! on one computer covers both.
//!
//! Logs never contain what was typed (only counts of keys), and they only go
//! to paired devices.

use std::path::PathBuf;

/// Most of a log sent to another device, from its end.
pub(crate) const MAX_LOG: usize = 4 * 1024 * 1024;

/// The recent log of this device's service, newest last, at most
/// [`MAX_LOG`] bytes, after a line saying what it runs.
pub(crate) fn own_log() -> String {
    let mut log = format!(
        "Lan Mouse {} on {} ({}), {}\n\n",
        crate::update::own_version(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        crate::discovery::local_name(),
    );
    let body = read_log();
    let budget = MAX_LOG.saturating_sub(log.len());
    let start = if body.len() > budget {
        // from the first whole line within the budget (a line break is
        // never inside a character)
        let cut = body.len() - budget;
        body.as_bytes()[cut..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(body.len(), |n| cut + n + 1)
    } else {
        0
    };
    log.push_str(&body[start..]);
    log
}

#[cfg(target_os = "macos")]
fn read_log() -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return String::new();
    };
    let dir = std::path::Path::new(&home).join("Library/Logs/Lan Mouse");
    // the previous log first, then the current one
    ["lan-mouse.old.log", "lan-mouse.log"]
        .iter()
        .filter_map(|f| std::fs::read(dir.join(f)).ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .collect()
}

#[cfg(not(target_os = "macos"))]
fn read_log() -> String {
    // the service's own journal (systemd user unit)
    std::process::Command::new("journalctl")
        .args([
            "--user",
            "-u",
            "lan-mouse",
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            "20000",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Where logs fetched from other devices are kept.
pub(crate) fn peer_log_path(name: &str) -> Option<PathBuf> {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(
        cache
            .join("lan-mouse")
            .join("logs")
            .join(format!("{safe}.log")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_says_what_it_comes_from_and_stays_small() {
        let log = own_log();
        assert!(log.starts_with("Lan Mouse "));
        assert!(log.len() <= MAX_LOG);
    }

    #[test]
    fn log_files_have_plain_names() {
        let path = peer_log_path("Nerses' MacBook/Air").unwrap();
        assert!(path.ends_with("lan-mouse/logs/Nerses__MacBook_Air.log"));
    }
}
