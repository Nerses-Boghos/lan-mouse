//! Files the user is dragging on this device, so a drag can carry them across
//! to another device (see `docs/file-transfer.md`).
//!
//! Only macOS so far: its drag pasteboard is readable by any process (see
//! `input_capture::current_drag`). On
//! Wayland, the compositor shows a drag only to the surface under the
//! pointer; reading it needs a surface of our own at the edge (not done yet).

use std::path::PathBuf;

#[cfg(target_os = "macos")]
mod platform {
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        // `Boolean` (unsigned char), not `bool`
        fn CGEventSourceButtonState(state: i32, button: u32) -> u8;
    }

    const COMBINED_SESSION_STATE: i32 = 0;
    const LEFT_BUTTON: u32 = 0;

    pub(crate) fn primary_button_down() -> bool {
        // SAFETY: plain query without pointers.
        unsafe { CGEventSourceButtonState(COMBINED_SESSION_STATE, LEFT_BUTTON) != 0 }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub(crate) fn primary_button_down() -> bool {
        false
    }
}

pub(crate) use platform::primary_button_down;

/// End the drag on this device without dropping it here: its files were
/// dropped on the other device, but here it still waits for the button
/// release (which went there). Released where it started, it ends without
/// effect (Escape doesn't end a drag that waits for its release).
pub(crate) fn cancel_local_drag() {
    input_capture::end_drag_where_it_started();
}

/// The files being dragged across right now, if the left button is held
/// for a drag that carries files.
pub(crate) fn dragged_files() -> Option<Vec<PathBuf>> {
    if !primary_button_down() {
        return None;
    }
    let files = input_capture::current_drag();
    match &files {
        Some(files) => log::info!("crossed while dragging {} items", files.len()),
        None => log::info!("crossed while dragging something other than files"),
    }
    files
}
