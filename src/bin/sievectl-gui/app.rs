use crate::model::*;
use crate::worker::{Req, Resp, Scripts, Worker};
use egui::{
    Align, Color32, ComboBox, Key, KeyboardShortcut, Layout, Modifiers, RichText, ScrollArea,
    TextEdit,
};
use serde::{Deserialize, Serialize};
use sievectl::managesieve::{ConnectOptions, TlsMode};
use sievectl::rules::{self, Op};
use std::path::PathBuf;

const SAVE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::S);

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    host: String,
    port: String,
    user: String,
    tls: TlsMode,
    ca_file: String,
    remember: bool,
    allow_plaintext: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            host: String::new(),
            port: "4190".into(),
            user: String::new(),
            tls: TlsMode::Starttls,
            ca_file: String::new(),
            remember: true,
            allow_plaintext: false,
        }
    }
}

enum DocMode {
    Rules(Vec<UiRule>),
    Raw(String),
}

struct Doc {
    name: String,
    original: String,
    mode: DocMode,
    on_server: bool,
    note: Option<String>,
}

impl Doc {
    fn compiled(&self) -> anyhow::Result<String> {
        match &self.mode {
            DocMode::Rules(r) => rules::compile(&to_ruleset(r)?),
            DocMode::Raw(t) => Ok(t.clone()),
        }
    }
    fn dirty(&self) -> bool {
        !self.on_server || self.compiled().map(|s| s != self.original).unwrap_or(true)
    }
}

#[derive(Clone)]
enum After {
    Open(String),
    NewScript,
    LogOut,
    Quit,
}

enum Modal {
    NewScript { name: String, raw: bool },
    Rename { old: String, new: String },
    Delete(String),
    Discard(After),
    ToRaw,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Rules,
    Sieve,
}

struct Conn {
    label: String,
    server: String,
    extensions: Vec<String>,
}

pub struct App {
    s: Settings,
    password: String,
    worker: Worker,
    conn: Option<Conn>,
    connecting: bool,
    /// Signing in on launch with the saved password: show a splash, not the form.
    auto_connecting: bool,
    scripts: Scripts,
    doc: Option<Doc>,
    sel: Option<usize>,
    tab: Tab,
    modal: Option<Modal>,
    status: Option<(String, bool)>,
    check: Option<Result<Option<String>, String>>,
    saving: Option<(String, String)>,
    /// IMAP folder list for the picker; None while loading or disconnected.
    folders: Option<Result<Vec<String>, String>>,
    allow_close: bool,
}

fn keyring_entry(s: &Settings) -> Option<keyring::Entry> {
    if s.user.trim().is_empty() || s.host.trim().is_empty() {
        return None;
    }
    sievectl::config::keychain_entry(&s.user, &s.host).ok()
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let s: Settings = cc
            .storage
            .and_then(|st| eframe::get_value(st, eframe::APP_KEY))
            .unwrap_or_default();
        let password = if s.remember {
            keyring_entry(&s)
                .and_then(|e| e.get_password().ok())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut app = App {
            s,
            password,
            worker: Worker::spawn(cc.egui_ctx.clone()),
            conn: None,
            connecting: false,
            auto_connecting: false,
            scripts: Vec::new(),
            doc: None,
            sel: None,
            tab: Tab::Rules,
            modal: None,
            status: None,
            check: None,
            saving: None,
            folders: None,
            allow_close: false,
        };
        if app.s.remember
            && !app.password.is_empty()
            && !app.s.host.trim().is_empty()
            && !app.s.user.trim().is_empty()
        {
            app.auto_connecting = true;
            app.connect();
        }
        app
    }

    fn info(&mut self, m: impl Into<String>) {
        self.status = Some((m.into(), false));
    }
    fn error(&mut self, m: impl Into<String>) {
        self.status = Some((m.into(), true));
    }

    fn is_active(&self, name: &str) -> bool {
        self.scripts.iter().any(|(n, a)| n == name && *a)
    }

    fn dirty(&self) -> bool {
        self.doc.as_ref().is_some_and(Doc::dirty)
    }

    // ---- actions -----------------------------------------------------------

    fn connect(&mut self) {
        let port = match self.s.port.trim().parse::<u16>() {
            Ok(p) => p,
            Err(_) => return self.error("Port must be a number"),
        };
        if self.s.tls == TlsMode::None && !self.s.allow_plaintext {
            return self.error(
                "Without TLS your password is sent in the clear; tick the box to allow it.",
            );
        }
        let opts = ConnectOptions {
            host: self.s.host.trim().to_string(),
            port,
            tls: self.s.tls,
            ca_file: (!self.s.ca_file.trim().is_empty())
                .then(|| PathBuf::from(self.s.ca_file.trim())),
            debug: false,
        };
        self.connecting = true;
        self.status = None;
        self.worker.send(Req::Connect {
            opts,
            user: self.s.user.trim().to_string(),
            pass: self.password.clone(),
        });
    }

    fn after(&mut self, a: After, ctx: &egui::Context) {
        match a {
            After::Open(n) => self.worker.send(Req::Get(n)),
            After::NewScript => {
                self.modal = Some(Modal::NewScript {
                    name: String::new(),
                    raw: false,
                })
            }
            After::LogOut => {
                // Forget the saved password so the next launch shows the login form.
                if let Some(e) = keyring_entry(&self.s) {
                    let _ = e.delete_credential();
                }
                self.password.clear();
                self.doc = None;
                self.worker.send(Req::Disconnect);
            }
            After::Quit => {
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    /// Run `a` now, or ask first if the open script has unsaved changes.
    fn guard(&mut self, a: After, ctx: &egui::Context) {
        if self.dirty() {
            self.modal = Some(Modal::Discard(a));
        } else {
            self.after(a, ctx);
        }
    }

    fn save(&mut self, activate: bool) {
        let Some(doc) = &self.doc else { return };
        match doc.compiled() {
            Ok(script) => {
                self.saving = Some((doc.name.clone(), script.clone()));
                self.worker.send(Req::Save {
                    name: doc.name.clone(),
                    script,
                    activate,
                });
            }
            Err(e) => self.error(format!("Can't save: {e:#}")),
        }
    }

    fn check(&mut self) {
        let Some(doc) = &self.doc else { return };
        match doc.compiled() {
            Ok(script) => self.worker.send(Req::Check(script)),
            Err(e) => self.check = Some(Err(format!("{e:#}"))),
        }
    }

    fn handle(&mut self, r: Resp) {
        match r {
            Resp::Connected { caps, scripts } => {
                self.connecting = false;
                self.auto_connecting = false;
                if let Some(e) = keyring_entry(&self.s) {
                    let res = if self.s.remember {
                        e.set_password(&self.password)
                    } else {
                        e.delete_credential().or(Ok(()))
                    };
                    if let Err(err) = res {
                        self.error(format!("Connected, but couldn't store the password: {err}"));
                    }
                }
                self.conn = Some(Conn {
                    label: format!("{} @ {}", self.s.user.trim(), self.s.host.trim()),
                    server: caps.get("IMPLEMENTATION").unwrap_or("").to_string(),
                    extensions: caps.sieve_extensions(),
                });
                if let Some((active, _)) = scripts.iter().find(|(_, a)| *a) {
                    self.worker.send(Req::Get(active.clone()));
                }
                self.scripts = scripts;
                self.folders = None;
                self.worker.send(Req::Folders);
            }
            Resp::Disconnected => {
                self.conn = None;
                self.folders = None;
                self.scripts.clear();
                self.doc = None;
                self.info("Logged out");
            }
            Resp::Scripts { scripts, msg } => {
                self.scripts = scripts;
                if let Some(m) = msg {
                    self.info(m);
                }
            }
            Resp::Loaded { name, content } => {
                let content = content.replace("\r\n", "\n");
                let (mode, original, note) = if content.trim().is_empty() {
                    (DocMode::Rules(Vec::new()), String::new(), None)
                } else {
                    match rules::extract(&content) {
                        Some(Ok(set)) => {
                            let orig = rules::compile(&set).unwrap_or_else(|_| content.clone());
                            (DocMode::Rules(set.rules.iter().map(UiRule::from_rule).collect()), orig, None)
                        }
                        Some(Err(e)) => (
                            DocMode::Raw(content.clone()),
                            content.clone(),
                            Some(format!("Embedded rules couldn't be read ({e:#}); showing the raw script.")),
                        ),
                        None => (
                            DocMode::Raw(content.clone()),
                            content.clone(),
                            Some("This script wasn't made with the rule builder, so it opens as raw Sieve.".into()),
                        ),
                    }
                };
                self.tab = if matches!(mode, DocMode::Rules(_)) {
                    Tab::Rules
                } else {
                    Tab::Sieve
                };
                self.sel = match &mode {
                    DocMode::Rules(r) if !r.is_empty() => Some(0),
                    _ => None,
                };
                self.doc = Some(Doc {
                    name,
                    original,
                    mode,
                    on_server: true,
                    note,
                });
                self.check = None;
                self.status = None;
            }
            Resp::Checked(r) => {
                match &r {
                    Ok(_) => self.info("The server accepted the script"),
                    Err(_) => self.error("The server rejected the script"),
                }
                self.check = Some(r);
            }
            Resp::Saved {
                name,
                warnings,
                scripts,
            } => {
                self.scripts = scripts;
                if let (Some(doc), Some((sname, script))) = (&mut self.doc, self.saving.take()) {
                    if doc.name == name && sname == name {
                        doc.original = script;
                        doc.on_server = true;
                    }
                }
                self.check = warnings.clone().map(|w| Ok(Some(w)));
                self.info(format!(
                    "Saved {name}{}",
                    if self.is_active(&name) {
                        " (active)"
                    } else {
                        ""
                    }
                ));
            }
            Resp::Deleted { name, scripts } => {
                self.scripts = scripts;
                if self.doc.as_ref().is_some_and(|d| d.name == name) {
                    self.doc = None;
                }
                self.info(format!("Deleted {name}"));
            }
            Resp::Renamed { old, new, scripts } => {
                self.scripts = scripts;
                if let Some(d) = &mut self.doc {
                    if d.name == old {
                        d.name = new.clone();
                    }
                }
                self.info(format!("Renamed {old} to {new}"));
            }
            Resp::Folders(r) => self.folders = Some(r),
            Resp::Error(e) => {
                self.connecting = false;
                self.auto_connecting = false;
                self.saving = None;
                self.error(e);
            }
        }
    }

    // ---- views -------------------------------------------------------------

    fn connect_view(&mut self, ui: &mut egui::Ui) {
        if self.auto_connecting {
            ui.vertical_centered(|ui| {
                ui.add_space(160.0);
                ui.heading(RichText::new("Vera Colander").size(26.0));
                ui.add_space(16.0);
                ui.spinner();
                ui.label(format!(
                    "Signing in to {} as {}…",
                    self.s.host.trim(),
                    self.s.user.trim()
                ));
            });
            return;
        }
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.heading(RichText::new("Vera Colander").size(26.0));
            ui.label("Connect to your mail server's ManageSieve service");
            ui.add_space(16.0);
        });
        let w = 440.0;
        ui.horizontal(|ui| {
            ui.add_space(((ui.available_width() - w) / 2.0).max(0.0));
            egui::Frame::group(ui.style())
                .inner_margin(16.0)
                .show(ui, |ui| {
                    ui.set_width(w);
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        let mut submit = false;
                        egui::Grid::new("conn")
                            .num_columns(2)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label("Server");
                                ui.add(
                                    TextEdit::singleline(&mut self.s.host)
                                        .hint_text("mail.example.com")
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                                ui.label("Port");
                                ui.add(TextEdit::singleline(&mut self.s.port).desired_width(80.0));
                                ui.end_row();
                                ui.label("Username");
                                ui.add(
                                    TextEdit::singleline(&mut self.s.user)
                                        .hint_text("me@example.com")
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                                ui.label("Password");
                                let r = ui.add(
                                    TextEdit::singleline(&mut self.password)
                                        .password(true)
                                        .desired_width(300.0),
                                );
                                submit |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                                ui.end_row();
                                ui.label("Security");
                                ComboBox::from_id_salt("tls")
                                    .selected_text(tls_label(self.s.tls))
                                    .width(300.0)
                                    .show_ui(ui, |ui| {
                                        for t in
                                            [TlsMode::Starttls, TlsMode::Implicit, TlsMode::None]
                                        {
                                            ui.selectable_value(&mut self.s.tls, t, tls_label(t));
                                        }
                                    });
                                ui.end_row();
                                ui.label("CA certificate");
                                ui.add(
                                    TextEdit::singleline(&mut self.s.ca_file)
                                        .hint_text("optional: PEM file for a private CA")
                                        .desired_width(300.0),
                                );
                                ui.end_row();
                            });
                        ui.add_space(6.0);
                        ui.checkbox(
                            &mut self.s.remember,
                            "Remember password in the system keychain",
                        );
                        if self.s.tls == TlsMode::None {
                            ui.checkbox(
                                &mut self.s.allow_plaintext,
                                "Allow sending my password without encryption",
                            );
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            let ready = !self.connecting
                                && !self.s.host.trim().is_empty()
                                && !self.s.user.trim().is_empty()
                                && !self.password.is_empty();
                            if ui
                                .add_enabled(
                                    ready,
                                    egui::Button::new("Connect").min_size([100.0, 28.0].into()),
                                )
                                .clicked()
                                || (submit && ready)
                            {
                                self.connect();
                            }
                            if self.connecting {
                                ui.spinner();
                                ui.label("Connecting…");
                            }
                        });
                        if let Some((m, true)) = &self.status {
                            ui.add_space(6.0);
                            ui.colored_label(ui.visuals().error_fg_color, m);
                        }
                    });
                });
        });
    }

    fn scripts_panel(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if let Some(c) = &self.conn {
            ui.add_space(6.0);
            ui.label(RichText::new(&c.label).strong());
            if !c.server.is_empty() {
                ui.label(RichText::new(&c.server).weak().small());
            }
        }
        if ui
            .small_button("Log out")
            .on_hover_text("Disconnect and forget the saved password")
            .clicked()
        {
            self.guard(After::LogOut, ctx);
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.heading("Scripts");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("➕").on_hover_text("New script").clicked() {
                    self.guard(After::NewScript, ctx);
                }
                if ui.button("🔄").on_hover_text("Refresh").clicked() {
                    self.worker.send(Req::List);
                }
            });
        });
        ui.add_space(4.0);
        let open = self.doc.as_ref().map(|d| d.name.clone());
        let mut todo: Option<(u8, String)> = None;
        ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.with_layout(Layout::top_down_justified(Align::Min), |ui| {
                    for (name, active) in self.scripts.clone() {
                        let text = if active {
                            RichText::new(format!("★ {name}")).strong()
                        } else {
                            RichText::new(format!("    {name}"))
                        };
                        let r = ui.selectable_label(open.as_deref() == Some(&name), text);
                        if r.clicked() && open.as_deref() != Some(&name) {
                            todo = Some((0, name.clone()));
                        }
                        r.context_menu(|ui| {
                            if ui.button("Open").clicked() {
                                todo = Some((0, name.clone()));
                                ui.close();
                            }
                            if active {
                                if ui.button("Deactivate").clicked() {
                                    todo = Some((1, String::new()));
                                    ui.close();
                                }
                            } else if ui.button("Make active").clicked() {
                                todo = Some((1, name.clone()));
                                ui.close();
                            }
                            if ui.button("Rename…").clicked() {
                                todo = Some((2, name.clone()));
                                ui.close();
                            }
                            if ui.button("Delete…").clicked() {
                                todo = Some((3, name.clone()));
                                ui.close();
                            }
                        });
                    }
                    if self.scripts.is_empty() {
                        ui.label(RichText::new("No scripts on the server yet.").weak());
                    }
                });
            });
        ui.add_space(6.0);
        ui.label(RichText::new("★ marks the active script; only one runs at a time. Right-click a script for more.").weak().small());
        match todo {
            Some((0, n)) => self.guard(After::Open(n), ctx),
            Some((1, n)) => self.worker.send(Req::Activate(n)),
            Some((2, n)) => {
                self.modal = Some(Modal::Rename {
                    new: n.clone(),
                    old: n,
                })
            }
            Some((3, n)) => self.modal = Some(Modal::Delete(n)),
            _ => {}
        }
    }

    fn doc_view(&mut self, ui: &mut egui::Ui) {
        let Some(doc) = &self.doc else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Pick a script on the left, or create a new one with ➕.").weak(),
                );
            });
            return;
        };
        let name = doc.name.clone();
        let dirty = doc.dirty();
        let is_rules = matches!(doc.mode, DocMode::Rules(_));
        let active = self.is_active(&name);
        let compiled = doc.compiled();
        let note = doc.note.clone();
        let on_server = doc.on_server;

        // toolbar
        let mut act: Option<&str> = None;
        ui.horizontal(|ui| {
            ui.heading(&name);
            if active {
                ui.label(RichText::new("★ active").color(Color32::from_rgb(0xd9, 0xa4, 0x1e)));
            }
            if dirty {
                ui.label(RichText::new("• unsaved").color(ui.visuals().warn_fg_color));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if is_rules {
                    ui.menu_button("More…", |ui| {
                        if ui.button("Convert to raw Sieve…").clicked() {
                            act = Some("raw");
                            ui.close();
                        }
                    });
                }
                if !active && ui.button("Save & activate").clicked() {
                    act = Some("save_act");
                }
                let save = ui.add_enabled(dirty, egui::Button::new("💾 Save"));
                if save
                    .on_hover_text(format!(
                        "Validate and upload ({})",
                        ui.ctx().format_shortcut(&SAVE)
                    ))
                    .clicked()
                {
                    act = Some("save");
                }
                if ui
                    .button("✔ Check")
                    .on_hover_text("Ask the server to validate without saving")
                    .clicked()
                {
                    act = Some("check");
                }
                if dirty && on_server && ui.button("↺ Revert").clicked() {
                    act = Some("revert");
                }
            });
        });
        match act {
            Some("save") => self.save(false),
            Some("save_act") => self.save(true),
            Some("check") => self.check(),
            Some("revert") => self.worker.send(Req::Get(name.clone())),
            Some("raw") => self.modal = Some(Modal::ToRaw),
            _ => {}
        }

        // banners
        if let Some(n) = note {
            ui.colored_label(ui.visuals().warn_fg_color, n);
        }
        if let (Ok(script), Some(conn)) = (&compiled, &self.conn) {
            if !conn.extensions.is_empty() {
                let missing: Vec<String> = rules::required(script)
                    .into_iter()
                    .filter(|r| !conn.extensions.iter().any(|e| e.eq_ignore_ascii_case(r)))
                    .collect();
                if !missing.is_empty() {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        format!(
                            "⚠ The server doesn't list these extensions: {}",
                            missing.join(", ")
                        ),
                    );
                }
            }
        }
        let mut clear_check = false;
        if let Some(c) = &self.check {
            let (color, text) = match c {
                Ok(None) => (
                    Color32::from_rgb(0x3f, 0xa3, 0x4d),
                    "✔ The server accepted the script.".to_string(),
                ),
                Ok(Some(w)) => (
                    ui.visuals().warn_fg_color,
                    format!("Accepted with warnings:\n{}", w.trim()),
                ),
                Err(e) => (
                    ui.visuals().error_fg_color,
                    format!("✖ Server error:\n{}", e.trim()),
                ),
            };
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(color, RichText::new(text).monospace());
                    ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                        clear_check = ui.small_button("✖").clicked();
                    });
                });
            });
        }
        if clear_check {
            self.check = None;
        }

        ui.horizontal(|ui| {
            if is_rules {
                ui.selectable_value(&mut self.tab, Tab::Rules, "Rules");
                ui.selectable_value(&mut self.tab, Tab::Sieve, "Generated Sieve");
            } else {
                ui.selectable_value(&mut self.tab, Tab::Sieve, "Sieve script");
                self.tab = Tab::Sieve;
            }
        });
        ui.separator();

        if self.tab == Tab::Rules && is_rules {
            self.rules_view(ui);
        } else {
            self.sieve_view(ui, compiled);
        }
    }

    fn sieve_view(&mut self, ui: &mut egui::Ui, compiled: anyhow::Result<String>) {
        let Some(doc) = &mut self.doc else { return };
        match &mut doc.mode {
            DocMode::Raw(text) => {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(text)
                                .code_editor()
                                .desired_rows(30)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }
            DocMode::Rules(_) => match compiled {
                Ok(s) => {
                    ui.label(
                        RichText::new("Read-only: generated from your rules. The #@ block at the end stores the rules so they can be reopened.")
                            .weak()
                            .small(),
                    );
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add(
                                TextEdit::multiline(&mut s.as_str())
                                    .code_editor()
                                    .desired_width(f32::INFINITY),
                            );
                        });
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().error_fg_color, format!("⚠ {e:#}"));
                }
            },
        }
    }

    fn rules_view(&mut self, ui: &mut egui::Ui) {
        let Some(Doc {
            mode: DocMode::Rules(rules),
            ..
        }) = &mut self.doc
        else {
            return;
        };
        let sel = &mut self.sel;
        let folders = self.folders.as_ref();
        let mut reload = false;
        if sel.is_some_and(|i| i >= rules.len()) {
            *sel = rules.len().checked_sub(1);
        }

        egui::Panel::left("rule_list")
            .resizable(true)
            .default_size(250.0)
            .show(ui, |ui| {
                rule_list(ui, rules, sel);
            });

        let preview = sel.and_then(|i| rules.get(i)).map(|r| {
            r.to_rule()
                .and_then(|r| rules::compile_rule(&r, &mut Default::default()))
        });
        egui::Panel::bottom("rule_preview")
            .resizable(true)
            .default_size(180.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.label(RichText::new("Sieve for this rule").strong());
                match preview {
                    Some(Ok(s)) => {
                        ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add(
                                    TextEdit::multiline(&mut s.as_str())
                                        .code_editor()
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                    Some(Err(e)) => {
                        ui.colored_label(ui.visuals().error_fg_color, format!("⚠ {e:#}"));
                    }
                    None => {
                        ui.label(RichText::new("Select a rule").weak());
                    }
                }
            });

        egui::CentralPanel::default().show(ui, |ui| match sel {
            Some(i) if *i < rules.len() => {
                let i = *i;
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| rule_editor(ui, &mut rules[i], i, folders, &mut reload));
            }
            _ => {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("No rule selected. Add one with “➕ Add rule”.").weak());
                });
            }
        });
        if reload {
            self.folders = None;
            self.worker.send(Req::Folders);
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.worker.busy() {
                ui.spinner();
            }
            if let Some((m, err)) = &self.status {
                let c = if *err {
                    ui.visuals().error_fg_color
                } else {
                    ui.visuals().text_color()
                };
                ui.colored_label(c, m.lines().next().unwrap_or(""))
                    .on_hover_text(m);
            }
            if let Some(c) = &self.conn {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("{} Sieve extensions", c.extensions.len())).weak(),
                    )
                    .on_hover_text(c.extensions.join("\n"));
                });
            }
        });
    }

    fn modals(&mut self, ctx: &egui::Context) {
        let Some(mut m) = self.modal.take() else {
            return;
        };
        let mut keep = true;
        let mut then: Option<After> = None;
        let names: Vec<String> = self.scripts.iter().map(|(n, _)| n.clone()).collect();
        let resp = egui::Modal::new(egui::Id::new("modal")).show(ctx, |ui| {
            ui.set_width(380.0);
            match &mut m {
                Modal::NewScript { name, raw } => {
                    ui.heading("New script");
                    ui.add_space(6.0);
                    let r = ui.add(TextEdit::singleline(name).hint_text("Script name, e.g. filters").desired_width(f32::INFINITY));
                    r.request_focus();
                    ui.radio_value(raw, false, "Build with rules (recommended)");
                    ui.radio_value(raw, true, "Blank Sieve script (hand-written)");
                    let n = name.trim().to_string();
                    let exists = names.contains(&n);
                    if exists {
                        ui.colored_label(ui.visuals().error_fg_color, "A script with that name exists.");
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let ok = !n.is_empty() && !exists;
                        if ui.add_enabled(ok, egui::Button::new("Create")).clicked()
                            || (ok && ui.input(|i| i.key_pressed(Key::Enter)))
                        {
                            let mode = if *raw {
                                DocMode::Raw("require [\"fileinto\"];\n\n".into())
                            } else {
                                DocMode::Rules(vec![UiRule::new(1)])
                            };
                            self.sel = if *raw { None } else { Some(0) };
                            self.tab = if *raw { Tab::Sieve } else { Tab::Rules };
                            self.doc = Some(Doc { name: n, original: String::new(), mode, on_server: false, note: None });
                            self.check = None;
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Rename { old, new } => {
                    ui.heading(format!("Rename “{old}”"));
                    ui.add(TextEdit::singleline(new).desired_width(f32::INFINITY));
                    let n = new.trim().to_string();
                    let ok = !n.is_empty() && n != *old && !names.contains(&n);
                    ui.horizontal(|ui| {
                        if ui.add_enabled(ok, egui::Button::new("Rename")).clicked() {
                            self.worker.send(Req::Rename(old.clone(), n));
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Delete(name) => {
                    ui.heading(format!("Delete “{name}”?"));
                    ui.label("The script is removed from the server. This can't be undone.");
                    let active = self.scripts.iter().any(|(n, a)| n == name && *a);
                    if active {
                        ui.colored_label(
                            ui.visuals().warn_fg_color,
                            "This is the active script. It will be deactivated first, so no filtering runs until you activate another.",
                        );
                    }
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Delete").color(ui.visuals().error_fg_color)).clicked() {
                            if active {
                                self.worker.send(Req::Activate(String::new()));
                            }
                            self.worker.send(Req::Delete(name.clone()));
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Discard(a) => {
                    ui.heading("Unsaved changes");
                    ui.label(format!(
                        "“{}” has changes that aren't on the server yet. Discard them?",
                        self.doc.as_ref().map(|d| d.name.as_str()).unwrap_or("")
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Discard").clicked() {
                            then = Some(a.clone());
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::ToRaw => {
                    ui.heading("Convert to raw Sieve?");
                    ui.label("You'll be able to hand-edit the script, but it can no longer be edited with the rule builder.");
                    ui.horizontal(|ui| {
                        if ui.button("Convert").clicked() {
                            if let Some(doc) = &mut self.doc {
                                match doc.compiled() {
                                    Ok(s) => {
                                        doc.mode = DocMode::Raw(rules::without_embedded(&s));
                                        self.tab = Tab::Sieve;
                                    }
                                    Err(e) => self.status = Some((format!("Fix the rules first: {e:#}"), true)),
                                }
                            }
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
            }
        });
        if resp.should_close() {
            keep = false;
        }
        if keep {
            self.modal = Some(m);
        }
        if let Some(a) = then {
            self.after(a, ctx);
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        for r in self.worker.poll() {
            self.handle(r);
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close && self.dirty() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.modal = Some(Modal::Discard(After::Quit));
        }
        if self.conn.is_some()
            && self.modal.is_none()
            && ctx.input_mut(|i| i.consume_shortcut(&SAVE))
            && self.dirty()
        {
            self.save(false);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.conn.is_none() {
            egui::CentralPanel::default().show(ui, |ui| self.connect_view(ui));
        } else {
            egui::Panel::left("scripts")
                .resizable(true)
                .default_size(220.0)
                .show(ui, |ui| self.scripts_panel(ui, &ctx));
            egui::CentralPanel::default().show(ui, |ui| self.doc_view(ui));
        }
        self.modals(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.s);
    }
}

fn tls_label(t: TlsMode) -> &'static str {
    match t {
        TlsMode::Starttls => "STARTTLS (port 4190, standard)",
        TlsMode::Implicit => "TLS from the start",
        TlsMode::None => "None (unencrypted)",
    }
}

fn rule_list(ui: &mut egui::Ui, rules: &mut Vec<UiRule>, sel: &mut Option<usize>) {
    ui.add_space(4.0);
    if ui.button("➕ Add rule").clicked() {
        rules.push(UiRule::new(rules.len() + 1));
        *sel = Some(rules.len() - 1);
    }
    ui.add_space(4.0);
    let mut mv: Option<(usize, isize)> = None;
    let mut del: Option<usize> = None;
    let n = rules.len();
    ScrollArea::vertical()
        .auto_shrink([false, true])
        .show(ui, |ui| {
            for (i, r) in rules.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut r.enabled, "").on_hover_text("Enabled");
                    let mut t = RichText::new(if r.name.trim().is_empty() {
                        "(unnamed)"
                    } else {
                        r.name.as_str()
                    });
                    if !r.enabled {
                        t = t.weak().strikethrough();
                    }
                    if ui.selectable_label(*sel == Some(i), t).clicked() {
                        *sel = Some(i);
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("🗑").on_hover_text("Delete rule").clicked() {
                            del = Some(i);
                        }
                        if ui
                            .add_enabled(i + 1 < n, egui::Button::new("⬇").small())
                            .clicked()
                        {
                            mv = Some((i, 1));
                        }
                        if ui
                            .add_enabled(i > 0, egui::Button::new("⬆").small())
                            .clicked()
                        {
                            mv = Some((i, -1));
                        }
                    });
                });
            }
            if rules.is_empty() {
                ui.label(RichText::new("No rules yet.").weak());
            }
        });
    ui.add_space(6.0);
    ui.label(RichText::new("Rules run top to bottom.").weak().small());
    if let Some((i, d)) = mv {
        let j = (i as isize + d) as usize;
        rules.swap(i, j);
        if *sel == Some(i) {
            *sel = Some(j);
        } else if *sel == Some(j) {
            *sel = Some(i);
        }
    }
    if let Some(i) = del {
        rules.remove(i);
        *sel = match *sel {
            Some(s) if s > i => Some(s - 1),
            Some(s) if s == i => (!rules.is_empty()).then(|| i.min(rules.len() - 1)),
            s => s,
        };
    }
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(12.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add_space(4.0);
}

fn rule_editor(
    ui: &mut egui::Ui,
    r: &mut UiRule,
    ri: usize,
    folders: Option<&Result<Vec<String>, String>>,
    reload: &mut bool,
) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Name");
        ui.add(TextEdit::singleline(&mut r.name).desired_width(320.0));
        ui.checkbox(&mut r.enabled, "Enabled");
    });

    section(ui, "When");
    match r.conds.len() {
        0 => {
            ui.label("Always: no conditions, so this applies to every message.");
        }
        1 => {
            ui.label("this condition matches:");
        }
        _ => {
            ui.horizontal(|ui| {
                ui.label("Match");
                ComboBox::from_id_salt(("any", ri))
                    .selected_text(if r.any { "any" } else { "all" })
                    .width(60.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut r.any, false, "all");
                        ui.selectable_value(&mut r.any, true, "any");
                    });
                ui.label("of these conditions:");
            });
        }
    }
    let mut remove = None;
    for (ci, c) in r.conds.iter_mut().enumerate() {
        if condition_row(ui, c, ri, ci) {
            remove = Some(ci);
        }
    }
    if let Some(ci) = remove {
        r.conds.remove(ci);
    }
    if ui.button("➕ Add condition").clicked() {
        r.conds.push(UiCond::new());
    }

    section(ui, "Then");
    let mut remove = None;
    let mut up = None;
    let n = r.actions.len();
    for (ai, a) in r.actions.iter_mut().enumerate() {
        let (rm, u) = action_row(ui, a, ri, ai, n, folders, reload);
        if rm {
            remove = Some(ai);
        }
        if u {
            up = Some(ai);
        }
    }
    if let Some(ai) = remove {
        r.actions.remove(ai);
    }
    if let Some(ai) = up {
        r.actions.swap(ai, ai - 1);
    }
    ui.menu_button("➕ Add action", |ui| {
        for k in ActKind::ALL {
            if ui.button(k.label()).clicked() {
                let mut a = UiAction::new(k);
                if k == ActKind::Flag {
                    a.text = "\\Seen".into();
                }
                r.actions.push(a);
                ui.close();
            }
        }
    });
    if r.actions.is_empty() {
        ui.colored_label(ui.visuals().warn_fg_color, "Add at least one action.");
    }

    ui.add_space(12.0);
    ui.checkbox(
        &mut r.stop,
        "Stop here: don't run later rules when this one matches",
    );
    ui.add_space(12.0);
}

fn condition_row(ui: &mut egui::Ui, c: &mut UiCond, ri: usize, ci: usize) -> bool {
    let mut remove = false;
    ui.horizontal_wrapped(|ui| {
        let row_w = ui.available_width();
        if ui
            .small_button("✖")
            .on_hover_text("Remove condition")
            .clicked()
        {
            remove = true;
        }
        let custom = field_label(&c.field).is_none();
        ComboBox::from_id_salt(("field", ri, ci))
            .selected_text(field_label(&c.field).unwrap_or("Header…"))
            .width(160.0)
            .show_ui(ui, |ui| {
                for (k, l) in FIELDS {
                    if ui
                        .selectable_label(c.field.eq_ignore_ascii_case(k), *l)
                        .clicked()
                    {
                        c.field = k.to_string();
                    }
                }
                ui.separator();
                if ui.selectable_label(custom, "Other header…").clicked() && !custom {
                    c.field = String::new();
                }
            });
        if custom {
            ui.add(
                TextEdit::singleline(&mut c.field)
                    .hint_text("Header-Name")
                    .desired_width(120.0),
            );
        }
        let is_size = c.field.eq_ignore_ascii_case("size");
        if is_size && !SIZE_OPS.contains(&c.op) {
            c.op = Op::Over;
        } else if !is_size && SIZE_OPS.contains(&c.op) {
            c.op = Op::Contains;
        }
        if !is_size {
            ui.toggle_value(&mut c.not, "not")
                .on_hover_text("Negate this condition");
        }
        let ops: &[Op] = if is_size { &SIZE_OPS } else { &TEXT_OPS };
        ComboBox::from_id_salt(("op", ri, ci))
            .selected_text(op_label(c.op))
            .width(120.0)
            .show_ui(ui, |ui| {
                for o in ops {
                    ui.selectable_value(&mut c.op, *o, op_label(*o));
                }
            });
        if c.op != Op::Exists {
            let hint = if is_size {
                "e.g. 10M, 500K"
            } else if c.op == Op::Regex {
                "regular expression"
            } else {
                "value  |  another value"
            };
            let w = if is_size {
                90.0
            } else {
                (row_w - 430.0 - if custom { 130.0 } else { 0.0 }).clamp(100.0, 300.0)
            };
            ui.add(
                TextEdit::singleline(&mut c.value)
                    .hint_text(hint)
                    .desired_width(w),
            )
            .on_hover_text("Separate alternatives with |");
            if !is_size {
                ui.toggle_value(&mut c.case_sensitive, "Aa")
                    .on_hover_text("Case-sensitive");
            }
        }
    });
    remove
}

/// 📁 button next to a folder box: pick from the server's IMAP folders,
/// filtered by what is already typed.
fn folder_picker(
    ui: &mut egui::Ui,
    text: &mut String,
    folders: Option<&Result<Vec<String>, String>>,
    reload: &mut bool,
    id: (usize, usize),
) {
    let btn = ui.button("📁").on_hover_text("Choose a folder on the server");
    let popup_id = ui.make_persistent_id(("folders", id));
    egui::Popup::menu(&btn)
        .id(popup_id)
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .show(|ui| {
            ui.set_min_width(260.0);
            match folders {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading folders…");
                    });
                }
                Some(Err(e)) => {
                    ui.colored_label(ui.visuals().error_fg_color, "Couldn't load folders");
                    ui.label(RichText::new(e).small().weak());
                    ui.label(RichText::new("You can still type the name.").small());
                    if ui.button("⟳ Try again").clicked() {
                        *reload = true;
                    }
                }
                Some(Ok(list)) => {
                    let q = text.trim().to_lowercase();
                    let shown: Vec<&String> = list
                        .iter()
                        .filter(|f| q.is_empty() || f.to_lowercase().contains(&q))
                        .collect();
                    let shown = if shown.is_empty() { list.iter().collect() } else { shown };
                    ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                        for f in shown {
                            if ui.selectable_label(text.trim() == f, f).clicked() {
                                *text = f.clone();
                                ui.close();
                            }
                        }
                    });
                    ui.separator();
                    if ui.small_button("⟳ Reload list").clicked() {
                        *reload = true;
                    }
                }
            }
        });
}

fn action_row(
    ui: &mut egui::Ui,
    a: &mut UiAction,
    ri: usize,
    ai: usize,
    n: usize,
    folders: Option<&Result<Vec<String>, String>>,
    reload: &mut bool,
) -> (bool, bool) {
    let mut remove = false;
    let mut up = false;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            remove = ui
                .small_button("✖")
                .on_hover_text("Remove action")
                .clicked();
            if ai > 0 && n > 1 {
                up = ui.small_button("⬆").on_hover_text("Move up").clicked();
            }
            ComboBox::from_id_salt(("act", ri, ai))
                .selected_text(a.kind.label())
                .width(170.0)
                .show_ui(ui, |ui| {
                    for k in ActKind::ALL {
                        ui.selectable_value(&mut a.kind, k, k.label());
                    }
                });
            match a.kind {
                ActKind::Fileinto => {
                    ui.add(
                        TextEdit::singleline(&mut a.text)
                            .hint_text("Folder, e.g. Lists/Debian")
                            .desired_width(200.0),
                    );
                    folder_picker(ui, &mut a.text, folders, reload, (ri, ai));
                    ui.checkbox(&mut a.create, "Create if missing");
                    ui.checkbox(&mut a.copy, "Also keep in Inbox");
                }
                ActKind::Redirect => {
                    ui.add(
                        TextEdit::singleline(&mut a.text)
                            .hint_text("someone@example.com")
                            .desired_width(220.0),
                    );
                    ui.checkbox(&mut a.copy, "Keep a copy");
                }
                ActKind::Reject => {
                    ui.add(
                        TextEdit::singleline(&mut a.text)
                            .hint_text("Reason sent to the sender")
                            .desired_width(300.0),
                    );
                }
                ActKind::Flag => {
                    ui.add(
                        TextEdit::singleline(&mut a.text)
                            .hint_text("\\Seen \\Flagged")
                            .desired_width(160.0),
                    );
                    ui.menu_button("Add flag", |ui| {
                        for (f, l) in FLAGS {
                            if ui.button(format!("{l}  ({f})")).clicked() {
                                if !a.text.split_whitespace().any(|x| x == *f) {
                                    if !a.text.trim().is_empty() {
                                        a.text.push(' ');
                                    }
                                    a.text.push_str(f);
                                }
                                ui.close();
                            }
                        }
                    });
                }
                ActKind::Keep | ActKind::Discard | ActKind::Vacation => {}
            }
        });
        if a.kind == ActKind::Vacation {
            egui::Grid::new(("vac", ri, ai))
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Subject");
                    ui.add(
                        TextEdit::singleline(&mut a.subject)
                            .hint_text("optional")
                            .desired_width(320.0),
                    );
                    ui.end_row();
                    ui.label("Every");
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut a.days)
                                .hint_text("7")
                                .desired_width(40.0),
                        );
                        ui.label("days per sender");
                    });
                    ui.end_row();
                    ui.label("From");
                    ui.add(
                        TextEdit::singleline(&mut a.from)
                            .hint_text("optional sender address")
                            .desired_width(320.0),
                    );
                    ui.end_row();
                    ui.label("Message");
                    ui.add(
                        TextEdit::multiline(&mut a.text)
                            .desired_rows(4)
                            .desired_width(420.0),
                    );
                    ui.end_row();
                });
        }
    });
    (remove, up)
}
