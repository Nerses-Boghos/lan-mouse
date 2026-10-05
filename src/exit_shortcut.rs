//! The exit shortcut: brings the cursor back to this device from whichever
//! device it is on, typed on this device's keyboard.
//!
//! Written as steps separated by spaces, each step keys pressed together
//! joined by `+`, every step within [`STEP_WINDOW`] of the last:
//!
//! ```text
//! Esc Esc Esc           Esc three times (the default)
//! Ctrl+Shift+Super+Alt  four keys held together
//! Ctrl+Esc Ctrl+Esc     twice Ctrl+Esc
//! ```
//!
//! Modifiers match either side (Ctrl is left or right Ctrl); Alt is Option
//! and Super is Cmd on a Mac.

use std::{
    fmt,
    str::FromStr,
    time::{Duration, Instant},
};

use input_event::scancode::Linux;

pub const DEFAULT: &str = "Esc Esc Esc";

/// Longest pause between the steps of a shortcut.
const STEP_WINDOW: Duration = Duration::from_secs(1);

/// One key of a step: any of these scancodes (both sides of a modifier).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    name: String,
    codes: Vec<Linux>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shortcut {
    steps: Vec<Vec<Key>>,
}

impl FromStr for Shortcut {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let steps = text
            .split_whitespace()
            .map(|step| {
                step.split('+')
                    .map(parse_key)
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        if steps.is_empty() {
            return Err("the shortcut is empty".into());
        }
        // Ctrl alone happens all the time while typing; several modifiers
        // held together are deliberate enough
        if steps
            .iter()
            .any(|s| s.len() < 3 && s.iter().all(|k| is_modifier(&k.codes)))
        {
            return Err("each step needs a key besides Ctrl, Shift, Alt and Super, \
                        or at least three of those held together"
                .into());
        }
        Ok(Self { steps })
    }
}

impl fmt::Display for Shortcut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let steps: Vec<String> = self
            .steps
            .iter()
            .map(|s| {
                s.iter()
                    .map(|k| k.name.as_str())
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect();
        f.write_str(&steps.join(" "))
    }
}

impl Shortcut {
    /// The shortcut the old `release_bind` setting held: its keys together.
    pub fn from_keys(keys: &[Linux]) -> Option<Self> {
        let step: Vec<Key> = keys
            .iter()
            .map(|&code| Key {
                name: key_name(code),
                codes: vec![code],
            })
            .collect();
        (!step.is_empty()).then(|| Self { steps: vec![step] })
    }
}

/// Follows the keys pressed for a [`Shortcut`].
pub struct Matcher {
    shortcut: Shortcut,
    /// steps done so far, and when the last one was
    done: usize,
    last: Option<Instant>,
}

impl Matcher {
    pub fn new(shortcut: Shortcut) -> Self {
        Self {
            shortcut,
            done: 0,
            last: None,
        }
    }

    /// `key` was just pressed, `is_down` tells which keys are held (it
    /// included): whether that completed the shortcut.
    pub fn press(&mut self, key: Linux, is_down: impl Fn(Linux) -> bool) -> bool {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) > STEP_WINDOW)
        {
            self.done = 0;
        }
        if !self.step_done(self.done, key, &is_down) {
            // a modifier of this step on its way down: keep going
            let held_on = self.shortcut.steps[self.done]
                .iter()
                .any(|k| k.codes.contains(&key) && is_modifier(&k.codes));
            if held_on {
                return false;
            }
            // anything else starts over, maybe as the first step
            self.done = 0;
            if !self.step_done(0, key, &is_down) {
                self.last = None;
                return false;
            }
        }
        self.done += 1;
        self.last = Some(now);
        if self.done == self.shortcut.steps.len() {
            self.done = 0;
            self.last = None;
            return true;
        }
        false
    }

    /// Whether pressing `key` completes step `step`: it belongs to the step
    /// and the step's other keys are held.
    fn step_done(&self, step: usize, key: Linux, is_down: &impl Fn(Linux) -> bool) -> bool {
        let keys = &self.shortcut.steps[step];
        keys.iter().any(|k| k.codes.contains(&key))
            && keys
                .iter()
                .all(|k| k.codes.contains(&key) || k.codes.iter().any(|&c| is_down(c)))
    }
}

fn is_modifier(codes: &[Linux]) -> bool {
    use Linux::*;
    codes.iter().all(|c| {
        matches!(
            c,
            KeyLeftCtrl
                | KeyRightCtrl
                | KeyLeftShift
                | KeyRightShift
                | KeyLeftAlt
                | KeyRightalt
                | KeyLeftMeta
                | KeyRightmeta
        )
    })
}

fn parse_key(name: &str) -> Result<Key, String> {
    use Linux::*;
    let lower = name.to_ascii_lowercase();
    let (name, codes) = match lower.as_str() {
        "" => return Err("a `+` without a key next to it".into()),
        "ctrl" | "control" => ("Ctrl", vec![KeyLeftCtrl, KeyRightCtrl]),
        "shift" => ("Shift", vec![KeyLeftShift, KeyRightShift]),
        "alt" | "option" | "opt" => ("Alt", vec![KeyLeftAlt, KeyRightalt]),
        "super" | "cmd" | "command" | "meta" | "win" => ("Super", vec![KeyLeftMeta, KeyRightmeta]),
        "esc" | "escape" => ("Esc", vec![KeyEsc]),
        "enter" | "return" => ("Enter", vec![KeyEnter]),
        "space" => ("Space", vec![KeySpace]),
        "tab" => ("Tab", vec![KeyTab]),
        "backspace" => ("Backspace", vec![KeyBackspace]),
        "`" | "grave" => ("`", vec![KeyGrave]),
        _ => {
            // letters, digits, F-keys and the rest by their scancode name
            let wanted = format!("key{lower}");
            let code = (0..=0x2ffu32)
                .filter_map(|n| Linux::try_from(n).ok())
                .find(|c| format!("{c:?}").to_ascii_lowercase() == wanted)
                .ok_or_else(|| format!("unknown key \"{name}\""))?;
            return Ok(Key {
                name: key_name(code),
                codes: vec![code],
            });
        }
    };
    Ok(Key {
        name: name.to_owned(),
        codes,
    })
}

/// A scancode's name as written in a shortcut.
fn key_name(code: Linux) -> String {
    use Linux::*;
    match code {
        KeyLeftCtrl | KeyRightCtrl => "Ctrl".into(),
        KeyLeftShift | KeyRightShift => "Shift".into(),
        KeyLeftAlt | KeyRightalt => "Alt".into(),
        KeyLeftMeta | KeyRightmeta => "Super".into(),
        KeyGrave => "`".into(),
        c => {
            let name = format!("{c:?}");
            name.strip_prefix("Key").unwrap_or(&name).to_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Linux::*;

    fn press_all(matcher: &mut Matcher, presses: &[(Linux, &[Linux])]) -> Vec<bool> {
        presses
            .iter()
            .map(|&(key, held)| matcher.press(key, |c| c == key || held.contains(&c)))
            .collect()
    }

    #[test]
    fn written_forms() {
        let s: Shortcut = "esc ESC Escape".parse().unwrap();
        assert_eq!(s.to_string(), "Esc Esc Esc");
        let s: Shortcut = "ctrl+shift+cmd+option".parse().unwrap();
        assert_eq!(s.to_string(), "Ctrl+Shift+Super+Alt");
        let s: Shortcut = "Ctrl+F12 q".parse().unwrap();
        assert_eq!(s.to_string(), "Ctrl+F12 Q");
        assert!("".parse::<Shortcut>().is_err());
        assert!("Ctrl+".parse::<Shortcut>().is_err());
        assert!("Ctrl+Nope".parse::<Shortcut>().is_err());
        // a lone modifier fires while typing
        assert!("Ctrl Ctrl".parse::<Shortcut>().is_err());
        assert!("Shift+Alt".parse::<Shortcut>().is_err());
    }

    #[test]
    fn three_taps() {
        let mut m = Matcher::new(DEFAULT.parse().unwrap());
        let fired = press_all(&mut m, &[(KeyEsc, &[]), (KeyEsc, &[]), (KeyEsc, &[])]);
        assert_eq!(fired, [false, false, true]);
        // starts over after firing
        let fired = press_all(&mut m, &[(KeyEsc, &[]), (KeyEsc, &[])]);
        assert_eq!(fired, [false, false]);
    }

    #[test]
    fn other_keys_start_over() {
        let mut m = Matcher::new(DEFAULT.parse().unwrap());
        let fired = press_all(
            &mut m,
            &[
                (KeyEsc, &[]),
                (KeyEsc, &[]),
                (KeyA, &[]),
                (KeyEsc, &[]),
                (KeyEsc, &[]),
            ],
        );
        assert_eq!(fired, [false; 5]);
        assert!(m.press(KeyEsc, |c| c == KeyEsc));
    }

    #[test]
    fn a_pause_starts_over() {
        let mut m = Matcher::new(DEFAULT.parse().unwrap());
        press_all(&mut m, &[(KeyEsc, &[]), (KeyEsc, &[])]);
        m.last = Some(Instant::now() - STEP_WINDOW - Duration::from_millis(10));
        assert!(!m.press(KeyEsc, |c| c == KeyEsc));
    }

    #[test]
    fn keys_held_together() {
        let mut m = Matcher::new("Ctrl+Shift+Super+Alt".parse().unwrap());
        let fired = press_all(
            &mut m,
            &[
                (KeyLeftCtrl, &[]),
                (KeyRightShift, &[KeyLeftCtrl]),
                (KeyLeftMeta, &[KeyLeftCtrl, KeyRightShift]),
                (KeyLeftAlt, &[KeyLeftCtrl, KeyRightShift, KeyLeftMeta]),
            ],
        );
        assert_eq!(fired, [false, false, false, true]);
    }

    #[test]
    fn combos_in_a_row() {
        let mut m = Matcher::new("Ctrl+Esc Ctrl+Esc".parse().unwrap());
        let fired = press_all(
            &mut m,
            &[
                (KeyLeftCtrl, &[]),
                (KeyEsc, &[KeyLeftCtrl]),
                (KeyEsc, &[KeyLeftCtrl]),
            ],
        );
        assert_eq!(fired, [false, false, true]);
        // Esc without Ctrl doesn't count
        let fired = press_all(&mut m, &[(KeyEsc, &[]), (KeyEsc, &[])]);
        assert_eq!(fired, [false, false]);
    }

    #[test]
    fn the_old_setting_carries_over() {
        let s = Shortcut::from_keys(&[KeyLeftCtrl, KeyLeftShift, KeyLeftMeta, KeyLeftAlt]).unwrap();
        assert_eq!(s.to_string(), "Ctrl+Shift+Super+Alt");
    }
}
