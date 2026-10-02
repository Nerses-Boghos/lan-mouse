#![allow(clashing_extern_declarations)]

//! The files of a drag in progress on macOS, read from the drag pasteboard
//! (readable by any process).
//!
//! The drag pasteboard keeps the last drag's contents after it ended. To
//! tell the current drag from an old one, its change count is noted at
//! every left-button press: a drag carries files only if they were written
//! after the press that is still held.

use std::{
    ffi::{CStr, c_char, c_void},
    path::PathBuf,
    sync::atomic::{AtomicIsize, Ordering},
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

/// Note a left-button press (cheap: one message to the pasteboard server).
pub(crate) fn note_press() {
    if let Some(count) = change_count() {
        AT_PRESS.store(count, Ordering::Relaxed);
    }
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
}
