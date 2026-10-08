//! Test helper: drives [`input_capture::NativeDrop`] the way Lan Mouse does:
//! waits until the pointer is on the overlay ("ready", then a press is
//! expected), and delivers FILE... a second after the press.
//!
//!     native_drop FILE...

use std::{path::PathBuf, time::Duration};

fn main() {
    let files: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    let drop = input_capture::NativeDrop::start().expect("no compositor");
    while !drop.ready() {
        if drop.finished() {
            println!("finished before it was ready");
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!("ready");
    // the files take a moment to arrive
    std::thread::sleep(Duration::from_secs(1));
    drop.deliver(files);
    println!("delivered");
    while !drop.finished() {
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("finished");
}
