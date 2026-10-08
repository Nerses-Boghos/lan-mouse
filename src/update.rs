//! Updates one device passes to another over their paired connection, so a
//! Mac never needs updating by hand: the computer that fetched a new build
//! sends the Mac's version along the next time they connect.
//!
//! The receiver installs it only when it is signed with the same certificate
//! as the Lan Mouse already installed. That also keeps macOS's permissions,
//! which belong to the signature.

use std::path::{Path, PathBuf};

/// Where the sending side finds builds for other devices (set by the
/// installer): `version` holds their commit, next to one zip per kind of
/// Mac (`lan-mouse-macos-arm64.zip`, `lan-mouse-macos-intel.zip`).
pub(crate) const BUILDS_ENV: &str = "LAN_MOUSE_MAC_UPDATES";

/// The Mac build for a device of this architecture (as announced, see
/// [`std::env::consts::ARCH`]), and its version, if there is one.
pub(crate) fn mac_build(arch: &str) -> Option<(PathBuf, String)> {
    let dir = PathBuf::from(std::env::var_os(BUILDS_ENV)?);
    let version = std::fs::read_to_string(dir.join("version")).ok()?;
    let version = version.trim();
    let zip = match arch {
        "aarch64" => "lan-mouse-macos-arm64.zip",
        "x86_64" => "lan-mouse-macos-intel.zip",
        _ => return None,
    };
    let zip = dir.join(zip);
    (zip.is_file() && !version.is_empty()).then(|| (zip, version.to_owned()))
}

/// Largest update taken (a Mac build is about 16 MB).
pub(crate) const MAX_UPDATE: u64 = 256 * 1024 * 1024;

/// An update is one zip file of a reasonable size.
pub(crate) fn check_offer(offer: &crate::transfer::Offer) -> Result<(), String> {
    match offer.entries.as_slice() {
        [entry]
            if entry.kind == crate::transfer::EntryKind::File
                && entry.path.ends_with(".zip")
                && !entry.path.contains('/') =>
        {
            if entry.size > MAX_UPDATE {
                Err(format!(
                    "an update of {} MB is too big",
                    entry.size / 1_000_000
                ))
            } else {
                Ok(())
            }
        }
        _ => Err("an update is one zip file".into()),
    }
}

/// Where an incoming update is put before installing it.
pub(crate) fn staging_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(Path::new(&home).join("Library/Caches/lan-mouse-update"))
}

/// This version, as devices tell each other (see [`crate::config::local_commit`]).
pub(crate) fn own_version() -> String {
    String::from_utf8_lossy(&crate::config::local_commit()).into_owned()
}

/// Whether `version` (as offered) is the one running here.
pub(crate) fn is_current(version: &str) -> bool {
    let own = own_version();
    !version.is_empty() && (version.starts_with(&own) || own.starts_with(version))
}

/// Install the app in `zip` in place of the running one, if it is signed by
/// the same certificate.
#[cfg(target_os = "macos")]
pub(crate) fn install(zip: &Path) -> Result<(), String> {
    use std::process::Command;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // <bundle>/Contents/MacOS/lan-mouse
    let app = exe
        .ancestors()
        .nth(3)
        .filter(|a| a.extension().is_some_and(|e| e == "app"))
        .ok_or("not running from an app bundle")?
        .to_owned();
    let folder = app.parent().ok_or("no folder around the app")?;
    let required = designated_requirement(&app)?;
    // ad hoc signatures name the exact build: nothing else would match
    if !required.contains("certificate leaf") {
        return Err(
            "this Lan Mouse isn't signed with a certificate; update it by hand once".into(),
        );
    }

    // unpacked next to the app: the same disk, so moving it is a rename
    let work = folder.join(".lan-mouse-update");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let result = (|| {
        run(Command::new("/usr/bin/ditto")
            .arg("-x")
            .arg("-k")
            .arg(zip)
            .arg(&work))?;
        let new = std::fs::read_dir(&work)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "app"))
            .ok_or("no app in the update")?;
        run(Command::new("/usr/bin/codesign")
            .args(["--verify", "--deep", "--strict"])
            .arg(format!("-R={required}"))
            .arg(&new))
        .map_err(|e| format!("not signed like the installed Lan Mouse: {e}"))?;
        // never back to an older build (with problems fixed since)
        let output = Command::new(new.join("Contents/MacOS/lan-mouse"))
            .arg("--version")
            .output()
            .map_err(|e| e.to_string())?;
        let built = build_time_of(&String::from_utf8_lossy(&output.stdout))
            .ok_or("the update doesn't say when it was built")?;
        if is_older(&built, crate::config::build_time()) {
            return Err(format!(
                "the update is older than this version (built {built})"
            ));
        }

        let old = folder.join(".Lan Mouse.app.old");
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(&app, &old).map_err(|e| e.to_string())?;
        if let Err(e) = std::fs::rename(&new, &app) {
            let _ = std::fs::rename(&old, &app);
            return Err(e.to_string());
        }
        let _ = std::fs::remove_dir_all(&old);
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

/// The build time in `--version` output ("build_time:2026-10-06 18:47:25 +00:00").
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn build_time_of(version: &str) -> Option<String> {
    version
        .lines()
        .find_map(|l| l.trim().strip_prefix("build_time:"))
        .map(|t| t.trim().to_owned())
}

/// Whether build time `a` is before `b` (both as `--version` prints them,
/// each with its own UTC offset). Unreadable times count as older.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_older(a: &str, b: &str) -> bool {
    match (utc_seconds(a), utc_seconds(b)) {
        (Some(a), Some(b)) => a < b,
        _ => true,
    }
}

/// "2026-10-06 18:47:25 +03:00" as seconds since 1970 (UTC).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn utc_seconds(time: &str) -> Option<i64> {
    let mut parts = time.split_whitespace();
    let (date, clock, offset) = (parts.next()?, parts.next()?, parts.next()?);
    let num = |s: &str| s.parse::<i64>().ok();
    let d: Vec<i64> = date.split('-').map(num).collect::<Option<_>>()?;
    let c: Vec<i64> = clock.split(':').map(num).collect::<Option<_>>()?;
    let (sign, off) = offset.split_at(1);
    let o: Vec<i64> = off.split(':').map(num).collect::<Option<_>>()?;
    let ([y, m, day], [hh, mm, ss], [oh, om]) = (d.as_slice(), c.as_slice(), o.as_slice()) else {
        return None;
    };
    // days since 1970-01-01 (Howard Hinnant's days_from_civil)
    let y = if *m <= 2 { y - 1 } else { *y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let offset = (oh * 3600 + om * 60) * if sign == "-" { -1 } else { 1 };
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - offset)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn install(_zip: &Path) -> Result<(), String> {
    Err("updates are only installed this way on a Mac".into())
}

/// Start the updated app: the service is restarted by macOS once this one
/// exits (its launch agent keeps it alive); the menu bar app is restarted
/// here, from a process of its own that outlives this one.
#[cfg(target_os = "macos")]
pub(crate) fn restart_app() {
    use std::os::unix::process::CommandExt;
    let script = "sleep 2; osascript -e 'quit app \"Lan Mouse\"' >/dev/null 2>&1; sleep 1; \
                  launchctl kickstart \"gui/$(id -u)/org.omarchy.lan-mouse.autostart\" >/dev/null 2>&1";
    if let Err(e) = std::process::Command::new("/bin/sh")
        .args(["-c", script])
        .process_group(0)
        .spawn()
    {
        log::warn!("could not restart the menu bar app: {e}");
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn restart_app() {}

#[cfg(target_os = "macos")]
fn designated_requirement(app: &Path) -> Result<String, String> {
    let out = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r-"])
        .arg(app)
        .output()
        .map_err(|e| e.to_string())?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    text.lines()
        .find_map(|l| l.strip_prefix("designated => "))
        .map(str::to_owned)
        .ok_or_else(|| "the installed Lan Mouse has no signature".to_owned())
}

#[cfg(target_os = "macos")]
fn run(command: &mut std::process::Command) -> Result<(), String> {
    let out = command.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_are_found_by_architecture() {
        let dir = std::env::temp_dir().join(format!("lm-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("version"), "abcdef12\n").unwrap();
        std::fs::write(dir.join("lan-mouse-macos-arm64.zip"), b"zip").unwrap();
        // SAFETY: tests touching this variable run in this one test
        unsafe { std::env::set_var(BUILDS_ENV, &dir) };
        let (zip, version) = mac_build("aarch64").unwrap();
        assert_eq!(zip, dir.join("lan-mouse-macos-arm64.zip"));
        assert_eq!(version, "abcdef12");
        // no Intel build here, and no builds for other kinds of devices
        assert!(mac_build("x86_64").is_none());
        assert!(mac_build("riscv64").is_none());
        unsafe { std::env::remove_var(BUILDS_ENV) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn updates_are_one_zip_of_reasonable_size() {
        use crate::transfer::{Entry, EntryKind, Offer};
        let offer = |entries: Vec<Entry>| Offer {
            id: 1,
            entries,
            on_drop: false,
            release_drops: false,
            update: Some("abcdef12".into()),
            clipboard: false,
        };
        let file = |path: &str, size| Entry {
            path: path.into(),
            kind: EntryKind::File,
            size,
        };
        assert!(check_offer(&offer(vec![file("lan-mouse-macos-arm64.zip", 16_000_000)])).is_ok());
        assert!(check_offer(&offer(vec![file("a.zip", MAX_UPDATE + 1)])).is_err());
        assert!(check_offer(&offer(vec![file("evil.sh", 10)])).is_err());
        assert!(check_offer(&offer(vec![file("a/b.zip", 10)])).is_err());
        assert!(check_offer(&offer(vec![file("a.zip", 10), file("b.zip", 10)])).is_err());
        assert!(check_offer(&offer(vec![])).is_err());
    }

    #[test]
    fn older_builds_are_refused() {
        let version = "lan-mouse 0.11.0\nbranch:cursor-position\ncommit_hash:2c941ab1\nbuild_time:2026-10-06 18:47:25 +00:00\n";
        let built = build_time_of(version).unwrap();
        assert_eq!(built, "2026-10-06 18:47:25 +00:00");
        assert!(is_older(&built, "2026-10-08 10:00:00 +00:00"));
        assert!(!is_older("2026-10-09 00:00:00 +00:00", &built));
        assert!(build_time_of("lan-mouse 0.11.0").is_none());
        // the same moment in two time zones is not older
        assert!(!is_older(
            "2026-10-09 00:38:25 +03:00",
            "2026-10-08 21:38:25 +00:00"
        ));
        assert!(is_older(
            "2026-10-09 00:38:24 +03:00",
            "2026-10-08 21:38:25 +00:00"
        ));
        assert_eq!(utc_seconds("1970-01-01 00:00:00 +00:00"), Some(0));
        assert_eq!(utc_seconds("2000-03-01 00:00:00 +00:00"), Some(951_868_800));
        assert!(is_older("garbage", "2026-10-08 21:38:25 +00:00"));
    }

    #[test]
    fn the_running_version_is_current() {
        assert!(is_current(&own_version()));
        assert!(!is_current("00000000"));
        assert!(!is_current(""));
    }
}
