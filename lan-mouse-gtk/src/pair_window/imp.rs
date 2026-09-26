use std::sync::OnceLock;

use adw::subclass::prelude::*;
use glib::subclass::InitializingObject;
use gtk::{
    Button, CompositeTemplate, Label,
    glib::{self, subclass::Signal},
    prelude::*,
    template_callbacks,
};

#[derive(CompositeTemplate, Default)]
#[template(resource = "/de/feschber/LanMouse/pair_window.ui")]
pub struct PairWindow {
    #[template_child]
    pub title: TemplateChild<Label>,
    #[template_child]
    pub code: TemplateChild<Label>,
    #[template_child]
    pub details: TemplateChild<Label>,
}

#[glib::object_subclass]
impl ObjectSubclass for PairWindow {
    const NAME: &'static str = "PairWindow";
    const ABSTRACT: bool = false;

    type Type = super::PairWindow;
    type ParentType = adw::Window;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
        klass.bind_template_callbacks();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

#[template_callbacks]
impl PairWindow {
    #[template_callback]
    fn handle_accept(&self, _: Button) {
        self.obj().emit_by_name::<()>("accepted", &[]);
    }

    #[template_callback]
    fn handle_decline(&self, _: Button) {
        self.obj().emit_by_name::<()>("declined", &[]);
    }
}

impl ObjectImpl for PairWindow {
    fn signals() -> &'static [Signal] {
        static SIGNALS: OnceLock<Vec<Signal>> = OnceLock::new();
        SIGNALS.get_or_init(|| {
            vec![
                Signal::builder("accepted").build(),
                Signal::builder("declined").build(),
            ]
        })
    }
}

impl WidgetImpl for PairWindow {}
impl WindowImpl for PairWindow {}
impl ApplicationWindowImpl for PairWindow {}
impl AdwWindowImpl for PairWindow {}
