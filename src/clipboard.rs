//! Reading and writing the system clipboard's text, using the platform's
//! standard tools: wl-clipboard on Linux, pbcopy/pbpaste on macOS.
//! Transfers between devices happen over the control channel, see
//! [`crate::control`].

use std::io;

#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::{io::AsyncWriteExt, process::Command};

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
pub(crate) async fn read() -> io::Result<Option<Vec<u8>>> {
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
pub(crate) async fn write(text: &[u8]) -> io::Result<()> {
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
pub(crate) async fn read() -> io::Result<Option<Vec<u8>>> {
    Ok(None)
}

#[cfg(not(unix))]
pub(crate) async fn write(_text: &[u8]) -> io::Result<()> {
    Err(io::Error::other(
        "clipboard sync is not supported on this platform",
    ))
}
