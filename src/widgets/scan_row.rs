use gtk::prelude::*;

use crate::models::ScanResult;

pub fn build_scan_row(result: &ScanResult) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    row.add_css_class("scan-row");
    row.add_css_class(result.status.css_class());

    let root = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.set_margin_top(10);
    root.set_margin_bottom(10);
    root.set_margin_start(10);
    root.set_margin_end(10);

    let top = gtk::Box::new(gtk::Orientation::Horizontal, 12);

    let id_label = gtk::Label::new(Some(&format!("#{}", result.check.id)));
    id_label.set_width_chars(4);
    id_label.set_xalign(0.0);
    id_label.add_css_class("dim-label");

    let iface = gtk::Label::new(Some(result.check.interface.as_str()));
    iface.add_css_class("pill");

    let param = gtk::Label::new(Some(&result.check.param));
    param.set_hexpand(true);
    param.set_xalign(0.0);
    param.add_css_class("param-label");

    let status = gtk::Label::new(Some(result.status.label()));
    status.add_css_class("pill");
    status.add_css_class(result.status.css_class());

    top.append(&id_label);
    top.append(&iface);
    top.append(&param);
    top.append(&status);

    let bottom = gtk::Box::new(gtk::Orientation::Horizontal, 16);
    let current = gtk::Label::new(Some(&format!("Текущее: {}", result.current_value)));
    current.set_xalign(0.0);
    current.add_css_class("dim-label");

    let target = gtk::Label::new(Some(&format!("Цель: {}", result.check.target_value)));
    target.set_xalign(0.0);
    target.add_css_class("dim-label");

    let section = gtk::Label::new(Some(&result.check.section));
    section.set_xalign(1.0);
    section.set_hexpand(true);
    section.add_css_class("dim-label");

    bottom.append(&current);
    bottom.append(&target);
    bottom.append(&section);

    let description = gtk::Label::new(Some(&result.check.description));
    description.set_wrap(true);
    description.set_xalign(0.0);

    root.append(&top);
    root.append(&description);
    root.append(&bottom);
    row.set_child(Some(&root));
    row
}
