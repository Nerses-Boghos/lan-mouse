mod imp;

use glib::Object;
use gtk::{gio, glib, subclass::prelude::ObjectSubclassIsExt};
use lan_mouse_ipc::Position;

glib::wrapper! {
    pub struct PairWindow(ObjectSubclass<imp::PairWindow>)
    @extends adw::Window, gtk::Window, gtk::Widget,
    @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
                gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl PairWindow {
    /// Asks whether to pair with `name`, which will sit at `pos` relative to
    /// this device. Emits `accepted` or `declined`.
    pub(crate) fn new(name: &str, code: &str, pos: Position) -> Self {
        let window: Self = Object::builder().build();
        let imp = window.imp();
        imp.title.set_text(&format!("Pair with {name}?"));
        imp.code.set_text(code);
        let (place, edge) = (pos.relative_phrase(), pos);
        imp.details.set_text(&format!(
            "Only pair if you just started pairing on {name} and it shows the same \
             code; otherwise decline. Once paired it will be {place}: move the \
             pointer past the {edge} edge of your screen to use it."
        ));
        window
    }
}
