#![allow(clashing_extern_declarations)]

//! The files of a drag in progress on macOS, read from the drag pasteboard
//! (readable by any process).
//!
//! The drag pasteboard keeps the last drag's contents after it ended. To
//! tell the current drag from an old one, its change count is noted at
//! every left-button press: a drag carries files only if they were written
//! after the press that is still held.
//!
//! The press's location is noted too: a drag dropped on another device
//! still waits here for its button release (which went there). Releasing it
//! where it started, on the dragged item itself, ends it without effect.

use std::{
    ffi::{CStr, c_char, c_void},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicIsize, Ordering},
    },
};

use core_foundation::{
    base::{CFType, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    number::CFNumber,
    string::CFString,
};
use core_graphics::{
    event::{CGEvent, CGEventTapLocation, CGEventType, CGMouseButton, EventField},
    event_source::{CGEventSource, CGEventSourceStateID},
    geometry::CGPoint,
    window::{copy_window_info, kCGNullWindowID, kCGWindowListOptionOnScreenOnly},
};

type Id = *mut c_void;
type Class = *mut c_void;
type Sel = *mut c_void;

#[link(name = "objc")]
extern "C" {
    fn objc_getClass(name: *const c_char) -> Class;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);
    #[link_name = "objc_msgSend"]
    fn msg_send_id_id(receiver: Id, selector: Sel, a: Id) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_ptr(receiver: Id, selector: Sel, value: *const c_char) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_isize(receiver: Id, selector: Sel) -> isize;
    #[link_name = "objc_msgSend"]
    fn msg_send_usize(receiver: Id, selector: Sel) -> usize;
    #[link_name = "objc_msgSend"]
    fn msg_send_id_usize(receiver: Id, selector: Sel, value: usize) -> Id;
    #[link_name = "objc_msgSend"]
    fn msg_send_ptr(receiver: Id, selector: Sel) -> *const c_char;
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {
    static NSPasteboardNameDrag: Id;
}

/// The drag pasteboard's change count at the last left-button press.
static AT_PRESS: AtomicIsize = AtomicIsize::new(isize::MIN);
/// Where the left button was last pressed.
static PRESSED_AT: Mutex<Option<(f64, f64)>> = Mutex::new(None);
/// The window where the drag started, noted when it crossed.
static DRAG_SOURCE: Mutex<Option<i64>> = Mutex::new(None);

/// Runs `f` with the drag pasteboard, inside an autorelease pool (the
/// objects involved are autoreleased, and this isn't the main thread).
fn with_pasteboard<T>(f: impl FnOnce(Id) -> Option<T>) -> Option<T> {
    // SAFETY: the pool is popped on every path; messages are sent to
    // objects of the classes they belong to, with matching prototypes.
    unsafe {
        let pool = objc_autoreleasePoolPush();
        let class = objc_getClass(c"NSPasteboard".as_ptr());
        let result = if class.is_null() {
            None
        } else {
            let pasteboard = msg_send_id_id(
                class,
                sel_registerName(c"pasteboardWithName:".as_ptr()),
                NSPasteboardNameDrag,
            );
            if pasteboard.is_null() {
                None
            } else {
                f(pasteboard)
            }
        };
        objc_autoreleasePoolPop(pool);
        result
    }
}

fn change_count() -> Option<isize> {
    with_pasteboard(|pasteboard| {
        // SAFETY: `changeCount` takes no arguments and returns NSInteger.
        Some(unsafe { msg_send_isize(pasteboard, sel_registerName(c"changeCount".as_ptr())) })
    })
}

/// Note a left-button press at `location` (cheap: one message to the
/// pasteboard server).
pub(crate) fn note_press(location: CGPoint) {
    if let Ok(mut at) = PRESSED_AT.lock() {
        *at = Some((location.x, location.y));
    }
    if let Some(count) = change_count() {
        AT_PRESS.store(count, Ordering::Relaxed);
    }
}

/// End the drag in progress here without dropping it anywhere new: move it
/// back to where it started, on the dragged item, and release it there
/// (the release that ends drags went to the other device). Only if the
/// window there is still the one the drag came from: otherwise the release
/// could drop the files into another app or folder, and the drag is left
/// for the user to put back. The events are marked as Lan Mouse's own, so
/// capture lets them through to this device.
pub fn end_drag_where_it_started() {
    let Some((x, y)) = PRESSED_AT.lock().ok().and_then(|at| *at) else {
        return;
    };
    let source = DRAG_SOURCE.lock().ok().and_then(|s| *s);
    let window = window_at(x, y);
    if source.is_none() || window != source {
        log::warn!("not ending the drag here: the window where it started changed");
        return;
    }
    // posted with pauses, so the drag follows to the start before letting
    // go, without holding up the caller
    std::thread::spawn(move || {
        let post = |kind| {
            let Ok(source) = CGEventSource::new(CGEventSourceStateID::HIDSystemState) else {
                return;
            };
            if let Ok(event) =
                CGEvent::new_mouse_event(source, kind, CGPoint::new(x, y), CGMouseButton::Left)
            {
                event.set_integer_value_field(
                    EventField::EVENT_SOURCE_USER_DATA,
                    crate::LOCAL_EVENT_MARKER,
                );
                event.post(CGEventTapLocation::HID);
            }
        };
        for _ in 0..3 {
            post(CGEventType::LeftMouseDragged);
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        post(CGEventType::LeftMouseUp);
    });
}

/// The frontmost ordinary window at `x`, `y` (global coordinates), by its
/// window number: menus, the Dock and drag images (layers above 0) don't
/// count; desktop icons (below 0) do.
fn window_at(x: f64, y: f64) -> Option<i64> {
    let windows = copy_window_info(kCGWindowListOptionOnScreenOnly, kCGNullWindowID)?;
    for item in windows.iter() {
        // SAFETY: the window list holds CFDictionary values; get rule keeps
        // the array's ownership.
        let window: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_get_rule(*item as CFDictionaryRef) };
        let number = |dict: &CFDictionary<CFString, CFType>, key: &str| {
            dict.find(CFString::new(key))
                .and_then(|v| v.downcast::<CFNumber>())
                .and_then(|n| n.to_f64())
        };
        if number(&window, "kCGWindowLayer").is_none_or(|layer| layer > 0.0) {
            continue;
        }
        let Some(bounds) = window
            .find(CFString::new("kCGWindowBounds"))
            .and_then(|v| v.downcast::<CFDictionary>())
        else {
            continue;
        };
        // SAFETY: same dictionary, viewed with its key and value types
        let bounds: CFDictionary<CFString, CFType> =
            unsafe { CFDictionary::wrap_under_get_rule(bounds.as_concrete_TypeRef()) };
        let (Some(left), Some(top), Some(width), Some(height)) = (
            number(&bounds, "X"),
            number(&bounds, "Y"),
            number(&bounds, "Width"),
            number(&bounds, "Height"),
        ) else {
            continue;
        };
        if x >= left && x < left + width && y >= top && y < top + height {
            return number(&window, "kCGWindowNumber").map(|id| id as i64);
        }
    }
    None
}

/// The files being dragged right now, if the left button is held for a
/// drag that carries files.
pub fn current_drag() -> Option<Vec<PathBuf>> {
    with_pasteboard(|pasteboard| {
        // SAFETY: see `with_pasteboard`; strings are copied before the pool
        // is popped.
        unsafe {
            let count = msg_send_isize(pasteboard, sel_registerName(c"changeCount".as_ptr()));
            if count <= AT_PRESS.load(Ordering::Relaxed) {
                // nothing written since the press: an old drag's contents
                return None;
            }
            let kind = msg_send_id_ptr(
                objc_getClass(c"NSString".as_ptr()),
                sel_registerName(c"stringWithUTF8String:".as_ptr()),
                c"NSFilenamesPboardType".as_ptr(),
            );
            let list = msg_send_id_id(
                pasteboard,
                sel_registerName(c"propertyListForType:".as_ptr()),
                kind,
            );
            if list.is_null() {
                return None;
            }
            let len = msg_send_usize(list, sel_registerName(c"count".as_ptr()));
            let mut files = Vec::with_capacity(len);
            for i in 0..len {
                let item = msg_send_id_usize(list, sel_registerName(c"objectAtIndex:".as_ptr()), i);
                let utf8 = msg_send_ptr(item, sel_registerName(c"UTF8String".as_ptr()));
                if !utf8.is_null() {
                    files.push(PathBuf::from(
                        CStr::from_ptr(utf8).to_string_lossy().into_owned(),
                    ));
                }
            }
            (!files.is_empty()).then_some(files)
        }
    })
    .inspect(|_| {
        // the drag is crossing: remember the window it started in
        let at = PRESSED_AT.lock().ok().and_then(|at| *at);
        let window = at.and_then(|(x, y)| window_at(x, y));
        if let Ok(mut source) = DRAG_SOURCE.lock() {
            *source = window;
        }
    })
}
