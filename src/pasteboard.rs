//! The macOS general pasteboard, for what pbcopy and pbpaste can't carry:
//! copied files (as in Finder) and images.
#![allow(clashing_extern_declarations)]

use std::{
    ffi::{CStr, CString, c_char, c_void},
    io,
    path::PathBuf,
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
    fn send(receiver: Id, selector: Sel) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_id(receiver: Id, selector: Sel, a: Id) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_id_id(receiver: Id, selector: Sel, a: Id, b: Id) -> bool;
    #[link_name = "objc_msgSend"]
    fn send_cstr(receiver: Id, selector: Sel, value: *const c_char) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_bytes(receiver: Id, selector: Sel, bytes: *const c_void, len: usize) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_usize(receiver: Id, selector: Sel) -> usize;
    #[link_name = "objc_msgSend"]
    fn send_index(receiver: Id, selector: Sel, index: usize) -> Id;
    #[link_name = "objc_msgSend"]
    fn send_ptr(receiver: Id, selector: Sel) -> *const c_void;
    #[link_name = "objc_msgSend"]
    fn send_bool(receiver: Id, selector: Sel, a: Id) -> bool;
}

#[link(name = "AppKit", kind = "framework")]
extern "C" {}

fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

fn class(name: &CStr) -> Class {
    unsafe { objc_getClass(name.as_ptr()) }
}

/// Runs `f` with the general pasteboard, inside an autorelease pool.
fn with_pasteboard<T>(f: impl FnOnce(Id) -> T) -> T {
    unsafe {
        let pool = objc_autoreleasePoolPush();
        let pasteboard = send(class(c"NSPasteboard"), sel(c"generalPasteboard"));
        let result = f(pasteboard);
        objc_autoreleasePoolPop(pool);
        result
    }
}

unsafe fn ns_string(s: &str) -> Id {
    let c = CString::new(s).unwrap_or_default();
    unsafe {
        send_cstr(
            class(c"NSString"),
            sel(c"stringWithUTF8String:"),
            c.as_ptr(),
        )
    }
}

unsafe fn rust_string(s: Id) -> Option<String> {
    if s.is_null() {
        return None;
    }
    let utf8 = unsafe { send_ptr(s, sel(c"UTF8String")) } as *const c_char;
    if utf8.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(utf8) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// The files copied in Finder (or anything putting file names there).
pub(crate) fn files() -> Option<Vec<PathBuf>> {
    with_pasteboard(|pasteboard| unsafe {
        let kind = ns_string("NSFilenamesPboardType");
        let list = send_id(pasteboard, sel(c"propertyListForType:"), kind);
        if list.is_null() {
            return None;
        }
        let count = send_usize(list, sel(c"count"));
        let paths = (0..count)
            .filter_map(|i| rust_string(send_index(list, sel(c"objectAtIndex:"), i)))
            .map(PathBuf::from)
            .collect();
        Some(paths)
    })
}

/// A copied image, as PNG.
pub(crate) fn png() -> Option<Vec<u8>> {
    with_pasteboard(|pasteboard| unsafe {
        let data = send_id(pasteboard, sel(c"dataForType:"), ns_string("public.png"));
        if data.is_null() {
            return None;
        }
        let len = send_usize(data, sel(c"length"));
        let bytes = send_ptr(data, sel(c"bytes")) as *const u8;
        if bytes.is_null() || len == 0 {
            return None;
        }
        Some(std::slice::from_raw_parts(bytes, len).to_vec())
    })
}

/// Put `paths` on the pasteboard as copied files, for pasting in Finder.
pub(crate) fn set_files(paths: &[PathBuf]) -> io::Result<()> {
    with_pasteboard(|pasteboard| unsafe {
        let urls = send(class(c"NSMutableArray"), sel(c"array"));
        for path in paths {
            let url = send_id(
                class(c"NSURL"),
                sel(c"fileURLWithPath:"),
                ns_string(&path.to_string_lossy()),
            );
            send_id(urls, sel(c"addObject:"), url);
        }
        send(pasteboard, sel(c"clearContents"));
        if send_bool(pasteboard, sel(c"writeObjects:"), urls) {
            Ok(())
        } else {
            Err(io::Error::other("the pasteboard refused the files"))
        }
    })
}

/// Put a PNG image on the pasteboard.
pub(crate) fn set_png(png: &[u8]) -> io::Result<()> {
    with_pasteboard(|pasteboard| unsafe {
        let data = send_bytes(
            class(c"NSData"),
            sel(c"dataWithBytes:length:"),
            png.as_ptr().cast(),
            png.len(),
        );
        send(pasteboard, sel(c"clearContents"));
        if send_id_id(
            pasteboard,
            sel(c"setData:forType:"),
            data,
            ns_string("public.png"),
        ) {
            Ok(())
        } else {
            Err(io::Error::other("the pasteboard refused the image"))
        }
    })
}
