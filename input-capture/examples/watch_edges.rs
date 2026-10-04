//! Test helper: watch the left screen edge for dragged files (the edge strip
//! Lan Mouse puts where another device is) and print what it sees.
//!
//!     watch_edges SECONDS

use std::time::{Duration, Instant};

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    input_capture::watch_drag_edges(vec![input_capture::Position::Left]);
    let end = Instant::now() + Duration::from_secs(seconds);
    let mut last = None;
    println!("watching");
    while Instant::now() < end {
        let now = input_capture::current_drag();
        if now != last {
            match &now {
                Some(files) => println!("seen: {}", files.len()),
                None => println!("gone"),
            }
            last = now;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
