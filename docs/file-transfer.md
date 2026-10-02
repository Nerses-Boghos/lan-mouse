# Dragging files between devices: design

Status: proposal, not implemented.

## Goal

Drag one or more files (or folders) in the file manager on one device, carry
them across the screen edge, and let go on the other device: the files arrive
there. Both directions, Mac ⇄ Linux (Hyprland/Omarchy first).

What users expect from Universal Control and the like, ordered by importance:

1. It never loses or corrupts a file, and never leaves half-written files
   behind as if they were complete.
2. It never blocks or slows the mouse and keyboard, however big the transfer.
3. Nothing arrives that the user didn't drag; a stranger can't push files.
4. It is obvious where the files went, and how far along a big transfer is.
5. Dropping straight into a specific folder or app window.

## Why this is hard

Drag and drop is deliberately locked down on both systems: only the app under
the pointer may see what is being dragged, and only an app with a window may
start a drag. Lan Mouse captures input below the windowing level, so it is in
neither position by default.

| | Mac is the source | Linux (Wayland) is the source |
|---|---|---|
| Notice a drag at the edge | the drag pasteboard is readable by any process; the button is already tracked | the drag belongs to the compositor; we only see it if we put a surface (window) under the pointer at the edge |
| | Mac is the target | Linux is the target |
| Let the user drop it there | start our own drag from a transparent window under the pointer (an `NSDraggingSession`) | start our own drag from a temporary layer-shell surface, which needs a button press on it |

The source side is reasonably well understood. Starting a native drag on the
target with emulated input is fragile, and Synergy and Barrier have struggled
with it for years. It is also not needed for goals 1 to 4.

## Proposal: in phases, risky parts proven first

### Phase 0: spikes, about one day, nothing shipped

Settle the two unknowns before committing to the design:

- **Mac:** at the moment of crossing while a file drag is in progress, can the
  daemon (a LaunchAgent, not the app) read the file URLs from the drag
  pasteboard? Which privacy prompts appear?
- **Hyprland:** does the input-capture barrier still fire during a drag? Can a
  1-pixel layer-shell surface at the edge receive the drag offer
  (`text/uri-list`) just before the pointer leaves?

If Hyprland can't do it, Linux → Mac drag waits, and we ship Mac → Linux
first (plus copy/paste of files, see the alternatives).

### Phase 1: drop anywhere, files land in Downloads

- **The drag:** you drag files on device A, carry them across the edge and
  release the button anywhere on device B.
- **On release:** B shows a notification right away ("Receiving 3 files from
  Mac…"), with progress for big transfers.
- **When done:** the files are in `~/Downloads` on B. The notification says so,
  with **Show in folder**. Name clashes get " (2)", like browsers do.
- **Cancelling:** pressing Esc while dragging, or crossing back before
  letting go, cancels.

This covers most real use, and needs no synthetic drag on the target.

### Phase 2: drop into a window, later and only if Phase 1 holds up

Start a native drag on the target from a temporary transparent surface under
the pointer, so the drop goes to the window under it. Files are then
transferred **before** the drop (apps read them immediately), so this phase
needs a size limit or a "transfer first" wait. It is fragile, so it gets its
own spike.

## Architecture

```
 device A (source)                                  device B (target)
 ┌──────────────┐  crossing + drag   ┌───────────┐                 ┌───────────┐
 │ input capture│ ─────────────────▶ │  service  │                 │  service  │
 │ drag watcher │  (file paths)      │  transfer │ ── offer ────▶  │  transfer │
 └──────────────┘                    │  sender   │ ◀── accept ──── │  receiver │
                                     │           │ ══ data ══════▶ │ → .part   │
                                     └───────────┘                 │ → rename  │
                                                                   └───────────┘
```

- **Channel:** a new control-channel message kind on its own TLS connection
  per transfer, mutually authenticated like the clipboard, paired devices
  only. The input channel (UDP/DTLS) is untouched, so a transfer can't slow
  the pointer.
- **Offer → accept → data**, no push without consent:
  1. The source sends an offer: a transfer id, then each entry with its
     relative path, size, kind (file or folder) and modification time.
  2. Only after the user lets go on B does B answer **accept** (or **decline**
     if they crossed back or pressed Esc).
  3. On accept, the files are streamed in order, each as
     `[entry index][length][bytes]`, in 256 KiB chunks.
- **Writing:** into `Downloads/.lan-mouse-<id>/…` as `*.part`, then
  fsync, rename into place, and remove the staging folder. A crash or
  disconnect leaves only the hidden staging folder, which is cleaned up at
  start.
- **Integrity:** TLS covers it in transit. After the last byte, the source
  sends the total length per entry and a SHA-256 over all of them, which B
  checks before the rename.
- **Progress and cancel:** B reports progress to frontends (the widget, the
  Mac app) as `TransferUpdate` events, and either side can cancel. A cancel
  stops the stream and deletes the staging folder.

## Security and safety (the "lots of issues")

- **Who:** only paired devices (certificate fingerprint), as for the clipboard.
  Offers from others are refused before reading them.
- **What:** only files the user is dragging at that moment. The offer is
  created from the drag at crossing time, and B accepts only right after a
  drop by the user on B. Nothing else in the protocol can write files.
- **Where:** names are untrusted input. Reject absolute paths, `..`, empty
  segments, NUL and path separators inside names, and Windows-reserved
  characters. Never follow symlinks, either when reading on A or when
  writing on B. Folders are recreated, symlinks inside them are skipped and
  reported, and special files (devices, sockets) are skipped.
- **How much:** check free disk space against the offer before accepting.
  Limits per transfer: 10,000 entries, nesting depth 64, 1 KiB per path. No
  size limit, but more than 2 GB asks for confirmation on B.
- **Mac specifics:**
  - **Received files:** they get the `com.apple.quarantine` attribute like
    downloads, so Gatekeeper still checks received apps and scripts.
  - **Privacy prompts:** reading from Desktop, Documents or Downloads, and
    writing to Downloads, trigger macOS privacy prompts for the background
    service on first use. They're expected, and the setup page explains them.
- **Linux specifics:** nothing is made executable. Permissions are not copied
  from the source; files get the user's default permissions.

## Failure modes, and what the user sees

| Situation | Behavior |
|---|---|
| Wi-Fi drops mid-transfer | the transfer fails after a 10 s stall, the staging folder is removed, and a notification says "Transfer from Mac failed: connection lost" |
| Disk full | refused before starting if the space is known to be short; otherwise fails like above |
| The other device sleeps or quits | the same as a dropped connection |
| User crosses back without dropping | the offer is withdrawn and nothing is sent |
| A second drag while one is running | queued; transfers run one at a time per device pair |
| Huge folder | only the dragged paths are read at the crossing, which is instant; walking the folders to build the offer happens in the background, so the crossing is never delayed |
| The dragged item isn't a file (text, an image from a browser) | ignored in Phase 1, the drag just ends; text could later go through the clipboard |

## Alternatives considered

- **Copy/paste of files** through the clipboard sync we already have. Copy
  in Finder, cross, paste in Nautilus. Most of the transfer code is shared,
  and it's much more reliable than drag and drop, but it's not what was
  asked. Recommended as an add-on once transfers exist: nearly free then.
- **A "Send to…" menu entry** in the file manager: dependable, but per file
  manager and not cross-platform.
- **Starting with native drop into windows:** best when it works, but
  fragile and slow to get right, and it would delay everything else.

## Testing

- **Unit:** path sanitizing (traversal, symlinks, odd names), the
  offer/accept/stream state machine, and staging-and-rename recovery.
- **End to end (sandbox):** two engines with dummy backends transfer a tree
  with a big file, unicode and odd names, an empty folder and a symlink.
  Plus disconnect mid-transfer, cancel, a full disk (small tmpfs) and a
  refused stranger.
- **Real devices:** a checklist in TESTING.md, both directions. Include a
  large (>2 GB) file over Wi-Fi while moving the mouse, to check that the
  pointer stays smooth.

## Effort

- **Phase 0:** about a day, needs the Mac for one session.
- **Phase 1:** a few days, plus a real-device test session.
- **Phase 2:** separate decision after Phase 1.
