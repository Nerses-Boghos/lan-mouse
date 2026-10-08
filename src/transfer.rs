//! Sending files and folders to a paired device, see `docs/file-transfer.md`.
//!
//! A transfer runs on a control channel connection of its own (TLS, both
//! devices authenticated and paired), so it never competes with the input
//! channel. The protocol after the opening `OFFER` frame:
//!
//! ```text
//! sender                              receiver
//!   OFFER {id, entries}  ───────────▶  checks every name and the free space
//!                        ◀───────────  ACCEPT | REFUSE {reason}
//!   CHUNK bytes …        ───────────▶  writes into a hidden staging folder
//!   END sha256           ───────────▶  verifies, moves into place
//!                        ◀───────────  DONE | REFUSE {reason}
//! ```
//!
//! A dragged transfer starts streaming as soon as the drag crosses, before
//! the user lets go (`on_drop` in the offer). The sender then reports the
//! outcome of the drag with a `DROP` or `CANCEL` frame, before, between or
//! after the data frames; the receiver moves the files into place only
//! after a `DROP`, and discards them on `CANCEL`.
//!
//! File contents follow the entries in order; their sizes delimit them.
//! Either side ends a transfer by closing the connection; the receiver then
//! removes the staging folder, so a cut-off transfer leaves nothing behind
//! that looks complete.

use std::{
    collections::HashSet,
    fs,
    future::Future,
    io,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const KIND_OFFER: u8 = 10;
const KIND_ACCEPT: u8 = 11;
pub(crate) const KIND_REFUSE: u8 = 12;
const KIND_CHUNK: u8 = 13;
const KIND_END: u8 = 14;
const KIND_DONE: u8 = 15;
const KIND_DROP: u8 = 16;
const KIND_CANCEL: u8 = 17;

/// How long a dragged transfer waits for the user to let go.
const DROP_WAIT: Duration = Duration::from_secs(10 * 60);
/// A release of the receiver's button counts as the drop only if no `CANCEL`
/// arrives within this long: taking the drag back to the sender also lets
/// go of the receiver's button (when the receiver stops emulating input).
const RELEASE_GRACE: Duration = Duration::from_millis(400);
/// How often the receiver's button is looked at while a drag may end there.
const BUTTON_POLL: Duration = Duration::from_millis(50);

/// Size of the data frames.
const CHUNK: usize = 256 * 1024;
/// Largest offer accepted: about 10 000 entries with long names.
pub(crate) const MAX_OFFER_SIZE: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_DEPTH: usize = 64;
const MAX_PATH: usize = 1024;
/// A transfer that makes no progress for this long has failed.
const STALL: Duration = Duration::from_secs(15);
/// Progress is reported at most this often.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
/// Names of staging folders, so leftovers can be recognized and removed.
const STAGING_PREFIX: &str = ".lan-mouse-transfer-";

#[derive(Debug, Error)]
pub(crate) enum TransferError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("unsafe name in the transfer: {0:?}")]
    UnsafeName(String),
    #[error("too many items ({0}, at most {MAX_ENTRIES})")]
    TooManyEntries(usize),
    #[error("not enough space: {needed} bytes needed, {available} free")]
    NoSpace { needed: u64, available: u64 },
    #[error("the other device refused: {0}")]
    Refused(String),
    #[error("unexpected message {0}")]
    UnexpectedKind(u8),
    #[error("message too large ({0} bytes)")]
    TooLarge(usize),
    #[error("the data doesn't match what was sent (damaged in transit)")]
    Corrupted,
    #[error("no progress for {} s", STALL.as_secs())]
    Stalled,
    #[error("nothing to send")]
    Empty,
    #[error("cancelled")]
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum EntryKind {
    File,
    Dir,
}

/// One file or folder of a transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// relative, `/`-separated; the first component is a dragged item
    pub(crate) path: String,
    pub(crate) kind: EntryKind,
    /// bytes, 0 for folders
    pub(crate) size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Offer {
    pub(crate) id: u64,
    pub(crate) entries: Vec<Entry>,
    /// a drag: keep the files until the sender reports the drop
    #[serde(default)]
    pub(crate) on_drop: bool,
    /// The drag may end where the sender can't see it: on the receiver,
    /// with its own mouse (the receiving device's mouse moved the pointer
    /// over to the sender and back). Then a release of the receiver's
    /// primary button counts as the drop too, unless a `CANCEL` follows
    /// right after (see [`RELEASE_GRACE`]).
    #[serde(default)]
    pub(crate) release_drops: bool,
    /// Not files for the user: a build of Lan Mouse itself, of this version,
    /// for the receiver to check and install (see [`crate::update`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) update: Option<String>,
    /// Files copied on the sender, for the receiver's clipboard: kept out of
    /// sight, ready to paste.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) clipboard: bool,
}

impl Offer {
    pub(crate) fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    pub(crate) fn files(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .count()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Refusal {
    reason: String,
}

/// What to send: the entries, and where each one's data comes from.
#[derive(Debug)]
pub(crate) struct Selection {
    pub(crate) entries: Vec<Entry>,
    /// the source of each entry, aligned with `entries`
    pub(crate) sources: Vec<PathBuf>,
    /// items left out: symlinks, sockets, devices, unreadable ones
    pub(crate) skipped: Vec<PathBuf>,
}

/// Collect `paths` (files and folders, recursively) for sending. Symbolic
/// links are never followed and special files are skipped, so a transfer
/// only ever carries the user's regular files.
pub(crate) fn select(paths: &[PathBuf]) -> Result<Selection, TransferError> {
    let mut selection = Selection {
        entries: vec![],
        sources: vec![],
        skipped: vec![],
    };
    let mut taken = HashSet::new();
    for path in paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            selection.skipped.push(path.clone());
            continue;
        };
        // two dragged items with the same name: keep the first
        if !taken.insert(name.to_owned()) {
            selection.skipped.push(path.clone());
            continue;
        }
        collect(path, name.to_owned(), 1, &mut selection)?;
    }
    if selection.entries.is_empty() {
        return Err(TransferError::Empty);
    }
    Ok(selection)
}

fn collect(
    path: &Path,
    relative: String,
    depth: usize,
    selection: &mut Selection,
) -> Result<(), TransferError> {
    if selection.entries.len() >= MAX_ENTRIES {
        return Err(TransferError::TooManyEntries(selection.entries.len() + 1));
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        selection.skipped.push(path.to_owned());
        return Ok(());
    };
    let kind = if meta.is_file() {
        EntryKind::File
    } else if meta.is_dir() && depth <= MAX_DEPTH {
        EntryKind::Dir
    } else {
        // symlinks, sockets, devices, too deep
        selection.skipped.push(path.to_owned());
        return Ok(());
    };
    if relative.len() > MAX_PATH {
        selection.skipped.push(path.to_owned());
        return Ok(());
    }
    selection.entries.push(Entry {
        path: relative.clone(),
        kind,
        size: if kind == EntryKind::File {
            meta.len()
        } else {
            0
        },
    });
    selection.sources.push(path.to_owned());
    if kind == EntryKind::Dir {
        let Ok(dir) = fs::read_dir(path) else {
            return Ok(());
        };
        let mut children: Vec<_> = dir.filter_map(Result::ok).collect();
        children.sort_by_key(|c| c.file_name());
        for child in children {
            match child.file_name().to_str() {
                Some(name) => collect(
                    &child.path(),
                    format!("{relative}/{name}"),
                    depth + 1,
                    selection,
                )?,
                None => selection.skipped.push(child.path()),
            }
        }
    }
    Ok(())
}

/// The relative path an entry from another device may be written to, or an
/// error if its name could escape the destination or isn't portable.
pub(crate) fn safe_relative(path: &str) -> Result<PathBuf, TransferError> {
    let unsafe_name = || TransferError::UnsafeName(path.to_owned());
    if path.is_empty() || path.len() > MAX_PATH {
        return Err(unsafe_name());
    }
    let mut safe = PathBuf::new();
    let mut depth = 0;
    for part in path.split('/') {
        depth += 1;
        let bad = part.is_empty()
            || part == "."
            || part == ".."
            || part.len() > 255
            || part.contains(['\0', '\\'])
            || part.chars().any(char::is_control)
            // Lan Mouse's own staging folders
            || part.starts_with(STAGING_PREFIX);
        if bad || depth > MAX_DEPTH {
            return Err(unsafe_name());
        }
        safe.push(part);
    }
    // belt and braces: only plain names may remain
    if !safe.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(unsafe_name());
    }
    Ok(safe)
}

/// Check every entry of an offer before accepting it.
pub(crate) fn check_offer(offer: &Offer) -> Result<(), TransferError> {
    if offer.entries.is_empty() {
        return Err(TransferError::Empty);
    }
    if offer.entries.len() > MAX_ENTRIES {
        return Err(TransferError::TooManyEntries(offer.entries.len()));
    }
    let mut seen = HashSet::new();
    for entry in &offer.entries {
        safe_relative(&entry.path)?;
        if entry.kind == EntryKind::Dir && entry.size != 0 {
            return Err(TransferError::UnsafeName(entry.path.clone()));
        }
        // the same path twice would overwrite what was just written
        if !seen.insert(entry.path.as_str()) {
            return Err(TransferError::UnsafeName(entry.path.clone()));
        }
    }
    Ok(())
}

/// The user's downloads folder.
pub(crate) fn downloads_dir() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    #[cfg(target_os = "linux")]
    {
        // XDG_DOWNLOAD_DIR="$HOME/Downloads" in user-dirs.dirs
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        if let Ok(dirs) = fs::read_to_string(config.join("user-dirs.dirs")) {
            for line in dirs.lines() {
                if let Some(value) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") {
                    let value = value.trim_matches('"');
                    let path = match value.strip_prefix("$HOME") {
                        Some(rest) => home.join(rest.trim_start_matches('/')),
                        None => PathBuf::from(value),
                    };
                    if path.is_absolute() && path != home {
                        return Some(path);
                    }
                }
            }
        }
    }
    Some(home.join("Downloads"))
}

/// Remove staging folders left behind by transfers that were cut off when
/// Lan Mouse stopped.
pub(crate) fn remove_leftovers(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let is_staging = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(STAGING_PREFIX));
        if is_staging && entry.file_type().is_ok_and(|t| t.is_dir()) {
            log::info!("removing an unfinished transfer: {:?}", entry.path());
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Free bytes for unprivileged users on the file system holding `dir`.
fn available_space(dir: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is NUL-terminated and `stat` is a valid out pointer.
        if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
            return None;
        }
        #[allow(clippy::unnecessary_cast)]
        Some(stat.f_bavail as u64 * stat.f_frsize as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

/// Move `items` into `dir`, renaming like a download when a name is taken;
/// returns where they are now.
pub(crate) fn move_into(items: &[PathBuf], dir: &Path) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(dir)?;
    items
        .iter()
        .map(|item| {
            let name = item
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .ok_or_else(|| io::Error::other("no file name"))?;
            let to = unique_name(dir, &name);
            fs::rename(item, &to)?;
            Ok(to)
        })
        .collect()
}

/// `name` in `dir`, or "name (2)", "name (3)" … if taken, like browsers.
fn unique_name(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if fs::symlink_metadata(&candidate).is_err() {
        return candidate;
    }
    // keep the extension: "photo (2).jpg"; not for ".bashrc"-like names
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .expect("a free name")
}

/// Progress of a transfer, for the user.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Progress {
    pub(crate) id: u64,
    pub(crate) files: usize,
    pub(crate) done: u64,
    pub(crate) total: u64,
}

/// Throttles progress reports.
struct Reporter<F: FnMut(Progress)> {
    report: F,
    last: Option<Instant>,
}

impl<F: FnMut(Progress)> Reporter<F> {
    fn progress(&mut self, progress: Progress, force: bool) {
        if force || self.last.is_none_or(|t| t.elapsed() >= PROGRESS_INTERVAL) {
            self.last = Some(Instant::now());
            (self.report)(progress);
        }
    }
}

async fn stalling<T>(
    f: impl Future<Output = Result<T, TransferError>>,
) -> Result<T, TransferError> {
    tokio::time::timeout(STALL, f)
        .await
        .map_err(|_| TransferError::Stalled)?
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    kind: u8,
    payload: &[u8],
) -> Result<(), TransferError> {
    stream.write_u8(kind).await?;
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// Read a frame whose payload is at most `limit` bytes.
pub(crate) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    limit: usize,
) -> Result<(u8, Vec<u8>), TransferError> {
    let kind = stream.read_u8().await?;
    let len = stream.read_u32().await? as usize;
    if len > limit {
        return Err(TransferError::TooLarge(len));
    }
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await?;
    Ok((kind, payload))
}

async fn refuse<S: AsyncWrite + Unpin>(stream: &mut S, error: &TransferError) {
    let reason = serde_json::to_vec(&Refusal {
        reason: error.to_string(),
    })
    .unwrap_or_default();
    let _ = write_frame(stream, KIND_REFUSE, &reason).await;
    let _ = stream.flush().await;
}

/// Turn down an offer without reading it further, saying why.
pub(crate) async fn refuse_offer<S: AsyncWrite + Unpin>(stream: &mut S, reason: &str) {
    let reason = serde_json::to_vec(&Refusal {
        reason: reason.to_owned(),
    })
    .unwrap_or_default();
    let _ = write_frame(stream, KIND_REFUSE, &reason).await;
    let _ = stream.flush().await;
}

fn refusal(payload: &[u8]) -> TransferError {
    let reason = serde_json::from_slice::<Refusal>(payload)
        .map(|r| r.reason)
        .unwrap_or_else(|_| "no reason given".to_owned());
    TransferError::Refused(reason)
}

/// The outcome of a drag: `None` while the user still holds it, then
/// `Some(true)` for a drop on the other device, `Some(false)` if cancelled.
pub(crate) type DragOutcome = tokio::sync::watch::Receiver<Option<bool>>;

/// Tell the receiver the outcome of the drag once it is known (and only
/// once): `Cancelled` ends the transfer.
async fn report_drag<S: AsyncWrite + Unpin>(
    stream: &mut S,
    drag: &mut Option<DragOutcome>,
) -> Result<(), TransferError> {
    let outcome = drag.as_ref().and_then(|d| *d.borrow());
    match outcome {
        None => Ok(()),
        Some(dropped) => {
            *drag = None;
            write_frame(stream, if dropped { KIND_DROP } else { KIND_CANCEL }, &[]).await?;
            stream.flush().await?;
            if dropped {
                Ok(())
            } else {
                Err(TransferError::Cancelled)
            }
        }
    }
}

/// Send `selection` as transfer `id` over `stream` (after the TLS handshake
/// with a paired device). With `drag`, the files are carried by a drag in
/// progress: the receiver keeps them only if it ends in a drop there.
/// `progress` gets throttled updates.
pub(crate) async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    id: u64,
    selection: &Selection,
    drag: Option<DragOutcome>,
    release_drops: bool,
    progress: impl FnMut(Progress),
) -> Result<(), TransferError> {
    let offer = Offer {
        id,
        entries: selection.entries.clone(),
        on_drop: drag.is_some(),
        release_drops: release_drops && drag.is_some(),
        update: None,
        clipboard: false,
    };
    send_offer(stream, offer, selection, drag, progress).await
}

/// [`send`], with the offer made already (e.g. for an update).
pub(crate) async fn send_offer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    offer: Offer,
    selection: &Selection,
    mut drag: Option<DragOutcome>,
    progress: impl FnMut(Progress),
) -> Result<(), TransferError> {
    let id = offer.id;
    let (files, total) = (offer.files(), offer.total_bytes());
    let mut reporter = Reporter {
        report: progress,
        last: None,
    };
    write_frame(stream, KIND_OFFER, &serde_json::to_vec(&offer)?).await?;
    stream.flush().await?;
    // the other side checks every name and its free space first
    match stalling(read_frame(stream, 64 * 1024)).await? {
        (KIND_ACCEPT, _) => {}
        (KIND_REFUSE, reason) => return Err(refusal(&reason)),
        (kind, _) => return Err(TransferError::UnexpectedKind(kind)),
    }

    let mut hash = Sha256::new();
    let mut done = 0u64;
    let mut buf = vec![0; CHUNK];
    for (entry, source) in selection.entries.iter().zip(&selection.sources) {
        if entry.kind != EntryKind::File {
            continue;
        }
        let mut file = tokio::fs::File::open(source).await?;
        // send exactly the size announced, even if the file changed since
        let mut left = entry.size;
        while left > 0 {
            let want = (left as usize).min(CHUNK);
            let n = file.read(&mut buf[..want]).await?;
            if n == 0 {
                // it shrank: the receiver would wait forever for the rest
                return Err(TransferError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{} changed while sending", source.display()),
                )));
            }
            hash.update(&buf[..n]);
            report_drag(stream, &mut drag).await?;
            stalling(write_frame(stream, KIND_CHUNK, &buf[..n])).await?;
            left -= n as u64;
            done += n as u64;
            reporter.progress(
                Progress {
                    id,
                    files,
                    done,
                    total,
                },
                false,
            );
        }
    }
    let digest: [u8; 32] = hash.finalize().into();
    write_frame(stream, KIND_END, &digest).await?;
    stream.flush().await?;
    // everything is there: wait for the user to let go (or give up)
    if let Some(mut outcome) = drag.take() {
        let decided = tokio::time::timeout(DROP_WAIT, outcome.wait_for(Option::is_some)).await;
        let dropped = matches!(decided, Ok(Ok(ref d)) if **d == Some(true));
        let mut decided = Some(tokio::sync::watch::channel(Some(dropped)).1);
        report_drag(stream, &mut decided).await?;
    }
    match stalling(read_frame(stream, 64 * 1024)).await? {
        (KIND_DONE, _) => {}
        (KIND_REFUSE, reason) => return Err(refusal(&reason)),
        (kind, _) => return Err(TransferError::UnexpectedKind(kind)),
    }
    reporter.progress(
        Progress {
            id,
            files,
            done,
            total,
        },
        true,
    );
    Ok(())
}

/// Removes a staging folder unless the transfer completed.
struct Staging {
    dir: PathBuf,
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Receive the transfer offered in `offer` (the payload of an `OFFER` frame
/// from a paired device) into `dest`. Returns what was saved there.
/// `button` tells whether this device's primary button is down, for drags
/// that may end here (see [`Offer::release_drops`]).
pub(crate) async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    offer: &[u8],
    dest: &Path,
    button: Option<&dyn Fn() -> bool>,
    progress: impl FnMut(Progress),
) -> Result<Vec<PathBuf>, TransferError> {
    let offer: Offer = serde_json::from_slice(offer)?;
    let checked = check_offer(&offer).and_then(|()| {
        fs::create_dir_all(dest)?;
        let needed = offer.total_bytes();
        match available_space(dest) {
            Some(available) if available < needed => {
                Err(TransferError::NoSpace { needed, available })
            }
            _ => Ok(()),
        }
    });
    if let Err(e) = checked {
        refuse(stream, &e).await;
        return Err(e);
    }

    // a hidden folder next to the destination: the same file system, so
    // moving the finished files into place is a rename
    let staging = Staging {
        dir: dest.join(format!("{STAGING_PREFIX}{:016x}", offer.id)),
    };
    let _ = fs::remove_dir_all(&staging.dir);
    fs::create_dir(&staging.dir)?;
    write_frame(stream, KIND_ACCEPT, &[]).await?;
    stream.flush().await?;

    // Frames are read on their own, so that waiting for the next one can
    // be combined with watching this device's button (reading a frame
    // can't be interrupted halfway).
    let (mut reader, mut writer) = tokio::io::split(&mut *stream);
    let (frames_tx, mut frames) = tokio::sync::mpsc::channel(4);
    let read_frames = async move {
        loop {
            let frame = read_frame(&mut reader, CHUNK).await;
            let failed = frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed {
                return;
            }
        }
    };
    let mut drop = DropWatch::new(&offer, button);
    let saved = {
        let work = receive_frames(&offer, &staging, dest, &mut frames, &mut drop, progress);
        tokio::pin!(read_frames, work);
        tokio::select! {
            biased;
            result = &mut work => result,
            // the connection ended: what's left in the queue decides
            () = &mut read_frames => work.await,
        }
    };
    let saved = match saved {
        Err(e @ TransferError::Corrupted) => {
            refuse(&mut writer, &e).await;
            return Err(e);
        }
        result => result?,
    };
    write_frame(&mut writer, KIND_DONE, &[]).await?;
    writer.flush().await?;
    Ok(saved)
}

/// Whether a dragged transfer was dropped here: by the sender's `DROP`, or
/// (with `release_drops`) by this device's button going up, unless the
/// sender cancels within [`RELEASE_GRACE`].
struct DropWatch<'a> {
    dropped: bool,
    button: Option<&'a dyn Fn() -> bool>,
    was_down: bool,
    released: Option<Instant>,
}

impl<'a> DropWatch<'a> {
    fn new(offer: &Offer, button: Option<&'a dyn Fn() -> bool>) -> Self {
        let button = button.filter(|_| offer.on_drop && offer.release_drops);
        let was_down = button.is_some_and(|down| down());
        Self {
            // not a drag: always wanted
            dropped: !offer.on_drop,
            button,
            was_down,
            // already up when the files arrived: let go right away
            released: button.filter(|_| !was_down).map(|_| Instant::now()),
        }
    }

    fn watch_button(&mut self) {
        let Some(down) = self.button.map(|down| down()) else {
            return;
        };
        if self.was_down && !down && self.released.is_none() {
            self.released = Some(Instant::now());
        }
        self.was_down = down;
    }

    fn decided(&mut self) -> bool {
        self.watch_button();
        if self
            .released
            .is_some_and(|at| at.elapsed() >= RELEASE_GRACE)
        {
            self.dropped = true;
        }
        self.dropped
    }
}

type Frames = tokio::sync::mpsc::Receiver<Result<(u8, Vec<u8>), TransferError>>;

/// The next data frame (or the end), taking note of `DROP` and stopping at
/// `CANCEL` in between.
async fn next_frame(
    frames: &mut Frames,
    drop: &mut DropWatch<'_>,
) -> Result<(u8, Vec<u8>), TransferError> {
    loop {
        let frame = tokio::time::timeout(STALL, frames.recv())
            .await
            .map_err(|_| TransferError::Stalled)?
            .ok_or(TransferError::Stalled)??;
        drop.watch_button();
        match frame {
            (KIND_DROP, _) => drop.dropped = true,
            (KIND_CANCEL, _) => return Err(TransferError::Cancelled),
            frame => return Ok(frame),
        }
    }
}

async fn receive_frames(
    offer: &Offer,
    staging: &Staging,
    dest: &Path,
    frames: &mut Frames,
    drop: &mut DropWatch<'_>,
    progress: impl FnMut(Progress),
) -> Result<Vec<PathBuf>, TransferError> {
    let (files, total) = (offer.files(), offer.total_bytes());
    let mut reporter = Reporter {
        report: progress,
        last: None,
    };
    let mut hash = Sha256::new();
    let mut done = 0u64;
    // data from the current chunk not written yet
    let mut pending: Vec<u8> = vec![];
    let mut pending_at = 0;
    for entry in &offer.entries {
        let path = staging.dir.join(safe_relative(&entry.path)?);
        if entry.kind == EntryKind::Dir {
            fs::create_dir_all(&path)?;
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let part = path.with_file_name(format!(
            "{}.part",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        ));
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .await?;
        let mut left = entry.size;
        while left > 0 {
            if pending_at == pending.len() {
                pending = match next_frame(frames, drop).await? {
                    (KIND_CHUNK, data) if !data.is_empty() => data,
                    (kind, _) => return Err(TransferError::UnexpectedKind(kind)),
                };
                pending_at = 0;
            }
            let n = ((pending.len() - pending_at) as u64).min(left) as usize;
            let data = &pending[pending_at..pending_at + n];
            file.write_all(data).await?;
            hash.update(data);
            pending_at += n;
            left -= n as u64;
            done += n as u64;
            reporter.progress(
                Progress {
                    id: offer.id,
                    files,
                    done,
                    total,
                },
                false,
            );
        }
        file.sync_all().await?;
        std::mem::drop(file);
        fs::rename(&part, &path)?;
        mark_downloaded(&path);
    }
    if pending_at != pending.len() {
        // more data than announced
        return Err(TransferError::Corrupted);
    }
    let digest = match next_frame(frames, drop).await? {
        (KIND_END, digest) => digest,
        (kind, _) => return Err(TransferError::UnexpectedKind(kind)),
    };
    let ours: [u8; 32] = hash.finalize().into();
    if digest.as_slice() != ours.as_slice() {
        return Err(TransferError::Corrupted);
    }

    // complete; a drag must still end in a drop here
    let deadline = Instant::now() + DROP_WAIT;
    while !drop.decided() {
        if Instant::now() > deadline {
            return Err(TransferError::Cancelled);
        }
        let poll = drop.button.is_some();
        tokio::select! {
            frame = frames.recv() => match frame {
                Some(Ok((KIND_DROP, _))) => drop.dropped = true,
                Some(Ok((KIND_CANCEL, _))) => return Err(TransferError::Cancelled),
                Some(Ok((kind, _))) => return Err(TransferError::UnexpectedKind(kind)),
                Some(Err(e)) => return Err(e),
                // the sender is gone before the user let go
                None => return Err(TransferError::Cancelled),
            },
            () = tokio::time::sleep(BUTTON_POLL), if poll => {}
        }
    }

    // move every dragged item into place, under a free name
    let mut saved = vec![];
    let mut moved = HashSet::new();
    for entry in &offer.entries {
        let top = entry.path.split('/').next().expect("checked");
        if moved.insert(top.to_owned()) {
            let target = unique_name(dest, top);
            fs::rename(staging.dir.join(top), &target)?;
            saved.push(target);
        }
    }
    reporter.progress(
        Progress {
            id: offer.id,
            files,
            done,
            total,
        },
        true,
    );
    Ok(saved)
}

/// Mark a received file the way browsers mark downloads, so the system
/// checks it before running it (macOS Gatekeeper).
fn mark_downloaded(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let value = format!("0083;{seconds:x};Lan Mouse;");
        let (Ok(path), Ok(name)) = (
            CString::new(path.as_os_str().as_bytes()),
            CString::new("com.apple.quarantine"),
        ) else {
            return;
        };
        // SAFETY: valid NUL-terminated strings and a buffer of the given size.
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "lan-mouse-transfer-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_that_could_escape_are_rejected() {
        for bad in [
            "",
            "/etc/passwd",
            "../x",
            "a/../../x",
            "a//b",
            "a/./b",
            "a\\..\\b",
            "nul\0byte",
            "line\nbreak",
            ".lan-mouse-transfer-0000/x",
        ] {
            assert!(safe_relative(bad).is_err(), "accepted {bad:?}");
        }
        for good in [
            "photo.jpg",
            "My Folder/notes (1).txt",
            "ünïcödé/日本.txt",
            ".hidden",
        ] {
            assert!(safe_relative(good).is_ok(), "refused {good:?}");
        }
        assert!(safe_relative(&"a/".repeat(70)).is_err(), "too deep");
    }

    #[test]
    fn offers_repeating_a_path_are_rejected() {
        let entry = |path: &str| Entry {
            path: path.to_owned(),
            kind: EntryKind::File,
            size: 1,
        };
        let offer = Offer {
            id: 1,
            entries: vec![entry("a"), entry("a")],
            on_drop: false,
            release_drops: false,
            update: None,
            clipboard: false,
        };
        assert!(check_offer(&offer).is_err());
    }

    #[test]
    fn taken_names_get_a_number() {
        let dir = temp_dir("names");
        fs::write(dir.join("photo.jpg"), "").unwrap();
        fs::write(dir.join("photo (2).jpg"), "").unwrap();
        fs::create_dir(dir.join("folder")).unwrap();
        assert_eq!(unique_name(&dir, "photo.jpg"), dir.join("photo (3).jpg"));
        assert_eq!(unique_name(&dir, "folder"), dir.join("folder (2)"));
        assert_eq!(unique_name(&dir, ".bashrc"), dir.join(".bashrc"));
        assert_eq!(unique_name(&dir, "new.txt"), dir.join("new.txt"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed() {
        let dir = temp_dir("select");
        let tree = dir.join("tree");
        fs::create_dir_all(tree.join("sub")).unwrap();
        fs::write(tree.join("sub/a.txt"), "aaa").unwrap();
        std::os::unix::fs::symlink("/etc", tree.join("etc")).unwrap();
        let selection = select(std::slice::from_ref(&tree)).unwrap();
        let paths: Vec<_> = selection.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["tree", "tree/sub", "tree/sub/a.txt"]);
        assert_eq!(selection.skipped, [tree.join("etc")]);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Send `paths` through an in-memory connection into `dest`.
    async fn transfer(paths: &[PathBuf], dest: &Path) -> Result<Vec<PathBuf>, TransferError> {
        let selection = select(paths)?;
        let (mut a, mut b) = duplex(64 * 1024);
        let sender = async { send(&mut a, 7, &selection, None, false, |_| {}).await };
        let receiver = async {
            let (kind, offer) = read_frame(&mut b, MAX_OFFER_SIZE).await?;
            assert_eq!(kind, KIND_OFFER);
            receive(&mut b, &offer, dest, None, |_| {}).await
        };
        let (sent, received) = tokio::join!(sender, receiver);
        sent?;
        received
    }

    #[tokio::test]
    async fn a_tree_arrives_intact() {
        let dir = temp_dir("intact");
        let src = dir.join("src");
        fs::create_dir_all(src.join("folder/empty")).unwrap();
        let big: Vec<u8> = (0..3 * CHUNK + 123).map(|i| (i % 251) as u8).collect();
        fs::write(src.join("folder/big.bin"), &big).unwrap();
        fs::write(src.join("folder/ünïcödé (1).txt"), "hi").unwrap();
        fs::write(src.join("empty.txt"), "").unwrap();
        let dest = dir.join("Downloads");
        // a name already taken in the destination
        fs::create_dir_all(dest.join("folder")).unwrap();

        let saved = transfer(&[src.join("folder"), src.join("empty.txt")], &dest)
            .await
            .unwrap();
        assert_eq!(saved, [dest.join("folder (2)"), dest.join("empty.txt")]);
        assert_eq!(fs::read(dest.join("folder (2)/big.bin")).unwrap(), big);
        assert_eq!(
            fs::read_to_string(dest.join("folder (2)/ünïcödé (1).txt")).unwrap(),
            "hi"
        );
        assert!(dest.join("folder (2)/empty").is_dir());
        assert_eq!(fs::read(dest.join("empty.txt")).unwrap(), b"");
        // nothing else left behind
        let mut names: Vec<_> = fs::read_dir(&dest)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["empty.txt", "folder", "folder (2)"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_cut_off_transfer_leaves_nothing() {
        let dir = temp_dir("cut");
        let src = dir.join("big.bin");
        fs::write(&src, vec![1u8; 2 * CHUNK]).unwrap();
        let dest = dir.join("Downloads");
        let selection = select(&[src]).unwrap();
        let (mut a, mut b) = duplex(64 * 1024);
        let sender = async {
            // offer and the first chunk, then the connection drops
            let offer = Offer {
                id: 9,
                entries: selection.entries.clone(),
                on_drop: false,
                release_drops: false,
                update: None,
                clipboard: false,
            };
            write_frame(&mut a, KIND_OFFER, &serde_json::to_vec(&offer).unwrap())
                .await
                .unwrap();
            let _ = read_frame(&mut a, 1024).await.unwrap();
            write_frame(&mut a, KIND_CHUNK, &vec![1u8; CHUNK])
                .await
                .unwrap();
            drop(a);
        };
        let receiver = async {
            let (_, offer) = read_frame(&mut b, MAX_OFFER_SIZE).await.unwrap();
            receive(&mut b, &offer, &dest, None, |_| {}).await
        };
        let ((), received) = tokio::join!(sender, receiver);
        assert!(received.is_err());
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0, "leftovers");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn tampered_data_is_detected() {
        let dir = temp_dir("tampered");
        let dest = dir.join("Downloads");
        let (mut a, mut b) = duplex(64 * 1024);
        let sender = async {
            let offer = Offer {
                id: 3,
                on_drop: false,
                release_drops: false,
                entries: vec![Entry {
                    path: "a.txt".to_owned(),
                    kind: EntryKind::File,
                    size: 4,
                }],
                update: None,
                clipboard: false,
            };
            write_frame(&mut a, KIND_OFFER, &serde_json::to_vec(&offer).unwrap())
                .await
                .unwrap();
            let _ = read_frame(&mut a, 1024).await.unwrap();
            write_frame(&mut a, KIND_CHUNK, b"evil").await.unwrap();
            // the digest of something else
            let digest: [u8; 32] = Sha256::digest(b"good").into();
            write_frame(&mut a, KIND_END, &digest).await.unwrap();
            read_frame(&mut a, 1024).await.unwrap().0
        };
        let receiver = async {
            let (_, offer) = read_frame(&mut b, MAX_OFFER_SIZE).await.unwrap();
            receive(&mut b, &offer, &dest, None, |_| {}).await
        };
        let (answer, received) = tokio::join!(sender, receiver);
        assert_eq!(answer, KIND_REFUSE);
        assert!(matches!(received, Err(TransferError::Corrupted)));
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 0, "leftovers");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn an_offer_escaping_the_destination_is_refused() {
        let dir = temp_dir("escape");
        let dest = dir.join("Downloads");
        let (mut a, mut b) = duplex(64 * 1024);
        let offer = Offer {
            id: 4,
            on_drop: false,
            release_drops: false,
            entries: vec![Entry {
                path: "../outside.txt".to_owned(),
                kind: EntryKind::File,
                size: 1,
            }],
            update: None,
            clipboard: false,
        };
        let payload = serde_json::to_vec(&offer).unwrap();
        let receiver = receive(&mut b, &payload, &dest, None, |_| {});
        let (received, answer) = tokio::join!(receiver, read_frame(&mut a, 1024));
        assert!(matches!(received, Err(TransferError::UnsafeName(_))));
        assert_eq!(answer.unwrap().0, KIND_REFUSE);
        assert!(!dir.join("outside.txt").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Drag `src` over and end the drag with `outcome` after `delay` (the
    /// user lets go while the data is still on its way, or after).
    async fn drag(
        src: &Path,
        dest: &Path,
        outcome: bool,
        delay: Duration,
    ) -> Result<Vec<PathBuf>, TransferError> {
        let selection = select(&[src.to_owned()])?;
        let (tx, rx) = tokio::sync::watch::channel(None);
        let (mut a, mut b) = duplex(64 * 1024);
        let sender = async { send(&mut a, 11, &selection, Some(rx), false, |_| {}).await };
        let user = async {
            tokio::time::sleep(delay).await;
            tx.send(Some(outcome)).unwrap();
        };
        let receiver = async {
            let (_, offer) = read_frame(&mut b, MAX_OFFER_SIZE).await?;
            receive(&mut b, &offer, dest, None, |_| {}).await
        };
        let (sent, (), received) = tokio::join!(sender, user, receiver);
        if outcome {
            sent?;
        }
        received
    }

    #[tokio::test]
    async fn dragged_files_arrive_once_dropped() {
        let dir = temp_dir("drop");
        let src = dir.join("big.bin");
        fs::write(&src, vec![7u8; 5 * CHUNK]).unwrap();
        let dest = dir.join("Downloads");
        // let go right away, while the data streams
        let saved = drag(&src, &dest, true, Duration::ZERO).await.unwrap();
        assert_eq!(fs::read(&saved[0]).unwrap(), vec![7u8; 5 * CHUNK]);
        // let go after everything arrived
        let saved = drag(&src, &dest, true, Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(saved, [dest.join("big (2).bin")]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_drag_taken_back_leaves_nothing() {
        let dir = temp_dir("taken-back");
        let src = dir.join("big.bin");
        fs::write(&src, vec![7u8; 5 * CHUNK]).unwrap();
        let dest = dir.join("Downloads");
        for delay in [Duration::ZERO, Duration::from_millis(300)] {
            let received = drag(&src, &dest, false, delay).await;
            assert!(
                matches!(received, Err(TransferError::Cancelled)),
                "{received:?}"
            );
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 0, "leftovers");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    /// A drag from the sender, ended on the receiver with its own mouse:
    /// the receiver's button goes up after `release`, and the sender cancels
    /// after `cancel` (if at all).
    async fn drag_ended_here(
        dest: &Path,
        release: Duration,
        cancel: Option<Duration>,
    ) -> Result<Vec<PathBuf>, TransferError> {
        let dir = dest.parent().unwrap();
        let src = dir.join("note.txt");
        fs::write(&src, "hi").unwrap();
        let selection = select(&[src])?;
        let (tx, rx) = tokio::sync::watch::channel(None);
        let (mut a, mut b) = duplex(64 * 1024);
        let down = std::sync::atomic::AtomicBool::new(true);
        let button = || down.load(std::sync::atomic::Ordering::Relaxed);
        let sender = async { send(&mut a, 12, &selection, Some(rx), true, |_| {}).await };
        let user = async {
            tokio::time::sleep(release).await;
            down.store(false, std::sync::atomic::Ordering::Relaxed);
            if let Some(cancel) = cancel {
                tokio::time::sleep(cancel).await;
                let _ = tx.send(Some(false));
            } else {
                // the sender never learns how it ended
                std::mem::forget(tx);
            }
        };
        let receiver = async {
            let (_, offer) = read_frame(&mut b, MAX_OFFER_SIZE).await?;
            receive(&mut b, &offer, dest, Some(&button), |_| {}).await
        };
        let (_, (), received) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), sender),
            user,
            receiver
        );
        received
    }

    #[tokio::test]
    async fn a_drag_can_end_with_the_receivers_own_mouse() {
        let dir = temp_dir("released-here");
        let dest = dir.join("Downloads");
        // let go here: dropped
        let saved = drag_ended_here(&dest, Duration::from_millis(100), None)
            .await
            .unwrap();
        assert_eq!(saved, [dest.join("note.txt")]);
        // the button went up because the drag went back: cancelled
        let back = drag_ended_here(
            &dest,
            Duration::from_millis(100),
            Some(Duration::from_millis(50)),
        )
        .await;
        assert!(matches!(back, Err(TransferError::Cancelled)), "{back:?}");
        assert_eq!(
            fs::read_dir(&dest).unwrap().count(),
            1,
            "only the first one"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn leftover_staging_folders_are_removed() {
        let dir = temp_dir("leftovers");
        fs::create_dir_all(dir.join(format!("{STAGING_PREFIX}00ab/x"))).unwrap();
        fs::write(dir.join("keep.txt"), "").unwrap();
        remove_leftovers(&dir);
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["keep.txt"]);
        fs::remove_dir_all(dir).unwrap();
    }
}
