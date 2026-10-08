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
    fn the_running_version_is_current() {
        assert!(is_current(&own_version()));
        assert!(!is_current("00000000"));
        assert!(!is_current(""));
    }
}
