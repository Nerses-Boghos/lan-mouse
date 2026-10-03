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
    use std::ffi::c_void;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        // `Boolean` (unsigned char), not `bool`
        fn CGEventSourceButtonState(state: i32, button: u32) -> u8;
        fn CGEventCreateKeyboardEvent(
            source: *const c_void,
            keycode: u16,
            key_down: bool,
        ) -> *mut c_void;
        fn CGEventPost(tap: u32, event: *mut c_void);
        fn CGEventSetIntegerValueField(event: *mut c_void, field: u32, value: i64);
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    const COMBINED_SESSION_STATE: i32 = 0;
    const LEFT_BUTTON: u32 = 0;
    const HID_EVENT_TAP: u32 = 0;
    const KEY_ESCAPE: u16 = 53;
    const EVENT_SOURCE_USER_DATA: u32 = 42;

    pub(crate) fn primary_button_down() -> bool {
        // SAFETY: plain query without pointers.
        unsafe { CGEventSourceButtonState(COMBINED_SESSION_STATE, LEFT_BUTTON) != 0 }
    }

    /// End the drag on this device without dropping it here: its files were
    /// dropped on the other device, but here the drag still waits for the
    /// button release (which went there). Escape cancels a drag; it is
    /// marked so that capture passes it to this device even while the
    /// keyboard controls the other one.
    pub(crate) fn cancel_local_drag() {
        for key_down in [true, false] {
            // SAFETY: a NULL source is allowed; the event is released after
            // posting.
            unsafe {
                let event = CGEventCreateKeyboardEvent(std::ptr::null(), KEY_ESCAPE, key_down);
                if event.is_null() {
                    return;
                }
                CGEventSetIntegerValueField(
                    event,
                    EVENT_SOURCE_USER_DATA,
                    input_capture::LOCAL_EVENT_MARKER,
                );
                CGEventPost(HID_EVENT_TAP, event);
                CFRelease(event);
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub(crate) fn primary_button_down() -> bool {
        false
    }

    pub(crate) fn cancel_local_drag() {}
}

pub(crate) use platform::{cancel_local_drag, primary_button_down};

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
