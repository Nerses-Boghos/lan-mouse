//! Reading and writing the system clipboard: text, copied files and images.
//! Linux uses wl-clipboard; macOS uses pbcopy/pbpaste for text and the
//! pasteboard itself for files and images (see [`crate::pasteboard`]).
//! Transfers between devices happen over the control channel, see
//! [`crate::control`].

use std::{io, path::PathBuf};

use sha2::{Digest, Sha256};

#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use tokio::{io::AsyncWriteExt, process::Command};

/// What the clipboard holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Clip {
    Text(Vec<u8>),
    /// files and folders copied in a file manager
    Files(Vec<PathBuf>),
    /// an image, as PNG
    Image(Vec<u8>),
}

impl Clip {
    /// Identifies the content, to not send back what just arrived.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        match self {
            Clip::Text(text) => {
                hash.update(b"text\0");
                hash.update(text);
            }
            Clip::Files(paths) => {
                hash.update(b"files\0");
                for path in paths {
                    hash.update(path.as_os_str().as_encoded_bytes());
                    hash.update(b"\0");
                }
            }
            Clip::Image(png) => {
                hash.update(b"image\0");
                hash.update(png);
            }
        }
        hash.finalize().into()
    }
}

/// The paths of the local files in a `text/uri-list`, decoded.
pub(crate) fn parse_uri_list(list: &str) -> Vec<PathBuf> {
    list.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("file://"))
        // file://host/path: only this machine's
        .filter_map(|l| l.strip_prefix("localhost").or(Some(l)))
        .filter(|l| l.starts_with('/'))
        .filter_map(percent_decode)
        .map(PathBuf::from)
        .collect()
}

/// `paths` as a `text/uri-list`.
pub(crate) fn uri_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| format!("file://{}\r\n", percent_encode(&p.to_string_lossy())))
        .collect()
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

/// What the clipboard holds, or `None` when nothing that can be shared.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) async fn read() -> io::Result<Option<Clip>> {
    let types = run_read(&["wl-paste", "--list-types"])
        .await?
        .unwrap_or_default();
    let types = String::from_utf8_lossy(&types);
    let has = |t: &str| types.lines().any(|l| l.trim() == t);
    if has("text/uri-list") {
        if let Some(list) =
            run_read(&["wl-paste", "--no-newline", "--type", "text/uri-list"]).await?
        {
            let paths: Vec<PathBuf> = parse_uri_list(&String::from_utf8_lossy(&list))
                .into_iter()
                .filter(|p| p.exists())
                .collect();
            if !paths.is_empty() {
                return Ok(Some(Clip::Files(paths)));
            }
        }
    }
    if has("image/png") {
        if let Some(png) = run_read(&["wl-paste", "--type", "image/png"]).await? {
            return Ok(Some(Clip::Image(png)));
        }
    }
    // wl-paste fails when the clipboard is empty or holds no text
    Ok(run_read(&["wl-paste", "--no-newline", "--type", "text"])
        .await?
        .map(Clip::Text))
}

#[cfg(target_os = "macos")]
pub(crate) async fn read() -> io::Result<Option<Clip>> {
    let native = tokio::task::spawn_blocking(|| {
        crate::pasteboard::files()
            .filter(|f| !f.is_empty())
            .map(Clip::Files)
            .or_else(|| crate::pasteboard::png().map(Clip::Image))
    })
    .await
    .map_err(io::Error::other)?;
    if native.is_some() {
        return Ok(native);
    }
    Ok(run_read(&["/usr/bin/pbpaste"]).await?.map(Clip::Text))
}

/// Put text on the clipboard.
#[cfg(unix)]
pub(crate) async fn write(text: &[u8]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let command: &[&str] = &["/usr/bin/pbcopy"];
    #[cfg(not(target_os = "macos"))]
    let command: &[&str] = &["wl-copy", "--type", "text/plain"];
    run_write(command, text).await
}

/// Put copied files on the clipboard, for pasting in a file manager.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) async fn write_files(paths: &[PathBuf]) -> io::Result<()> {
    run_write(
        &["wl-copy", "--type", "text/uri-list"],
        uri_list(paths).as_bytes(),
    )
    .await
}

#[cfg(target_os = "macos")]
pub(crate) async fn write_files(paths: &[PathBuf]) -> io::Result<()> {
    let paths = paths.to_vec();
    tokio::task::spawn_blocking(move || crate::pasteboard::set_files(&paths))
        .await
        .map_err(io::Error::other)?
}

/// Put a PNG image on the clipboard.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) async fn write_image(png: &[u8]) -> io::Result<()> {
    run_write(&["wl-copy", "--type", "image/png"], png).await
}

#[cfg(target_os = "macos")]
pub(crate) async fn write_image(png: &[u8]) -> io::Result<()> {
    let png = png.to_vec();
    tokio::task::spawn_blocking(move || crate::pasteboard::set_png(&png))
        .await
        .map_err(io::Error::other)?
}

/// Put `clip` on the clipboard.
pub(crate) async fn write_clip(clip: &Clip) -> io::Result<()> {
    // tests run on the desktop: leave its clipboard alone
    if cfg!(test) {
        return Ok(());
    }
    match clip {
        Clip::Text(text) => write(text).await,
        Clip::Files(paths) => write_files(paths).await,
        Clip::Image(png) => write_image(png).await,
    }
}

#[cfg(unix)]
async fn run_read(command: &[&str]) -> io::Result<Option<Vec<u8>>> {
    let output = Command::new(command[0])
        .args(&command[1..])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await?;
    Ok(output.status.success().then_some(output.stdout))
}

#[cfg(unix)]
async fn run_write(command: &[&str], data: &[u8]) -> io::Result<()> {
    let mut child = Command::new(command[0])
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin.write_all(data).await?;
    drop(stdin);
    // wl-copy forks to keep serving the selection; its parent exits right away
    child.wait().await?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) async fn read() -> io::Result<Option<Clip>> {
    Ok(None)
}

#[cfg(not(unix))]
pub(crate) async fn write(_text: &[u8]) -> io::Result<()> {
    Err(io::Error::other(
        "clipboard sync is not supported on this platform",
    ))
}

#[cfg(not(unix))]
pub(crate) async fn write_files(_paths: &[PathBuf]) -> io::Result<()> {
    write(&[]).await
}

#[cfg(not(unix))]
pub(crate) async fn write_image(_png: &[u8]) -> io::Result<()> {
    write(&[]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_lists_round_trip() {
        let paths = vec![
            PathBuf::from("/home/me/My Folder/ünï (1).txt"),
            PathBuf::from("/tmp/a%b"),
        ];
        let list = uri_list(&paths);
        assert!(list.starts_with("file:///home/me/My%20Folder/"));
        assert_eq!(parse_uri_list(&list), paths);
    }

    #[test]
    fn only_local_files_are_taken() {
        let list = "# comment\r\nfile:///a/b\r\nhttps://example.com/x\r\nfile://localhost/c\r\nfile://otherhost/d\r\n";
        assert_eq!(
            parse_uri_list(list),
            vec![PathBuf::from("/a/b"), PathBuf::from("/c")]
        );
    }

    #[test]
    fn contents_differ_by_kind() {
        assert_ne!(
            Clip::Text(b"/a".to_vec()).digest(),
            Clip::Files(vec![PathBuf::from("/a")]).digest()
        );
    }
}
