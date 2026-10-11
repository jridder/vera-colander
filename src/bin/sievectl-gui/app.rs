use crate::model::*;
use crate::worker::{InboxView, Req, Resp, Scripts, Worker};
use egui::{
    Align, Color32, ComboBox, Key, KeyboardShortcut, Layout, Modifiers, RichText, ScrollArea,
    TextEdit,
};
use serde::{Deserialize, Serialize};
use sievectl::managesieve::{ConnectOptions, TlsMode};
use sievectl::rules::{self, Op, SCRIPT_NAME};
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
    /// Show the raw server scripts, for debugging.
    advanced: bool,
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
            advanced: false,
        }
    }
}

/// All of the user's groups and rules: the one "vera-colander" script.
struct Workspace {
    groups: Vec<UiGroup>,
    /// The script as it is on the server ("" when there is none yet).
    original: String,
    on_server: bool,
    note: Option<String>,
}

impl Workspace {
    fn empty() -> Self {
        Workspace {
            groups: Vec::new(),
            original: String::new(),
            on_server: false,
            note: None,
        }
    }

    /// Open the server's "vera-colander" script.
    fn from_script(content: &str) -> Self {
        let content = content.replace("\r\n", "\n");
        match rules::extract(&content) {
            Some(Ok(set)) => {
                let set = set.grouped(rules::DEFAULT_GROUP);
                Workspace {
                    original: rules::compile(&set).unwrap_or_else(|_| content.clone()),
                    groups: set.groups.iter().map(UiGroup::from_group).collect(),
                    on_server: true,
                    note: None,
                }
            }
            other => {
                // Someone else wrote a script with our name: keep it as raw Sieve.
                let mut g = UiGroup::new(SCRIPT_NAME);
                let mut r = UiRule::new_raw(1);
                r.name = format!("Existing “{SCRIPT_NAME}” script");
                r.raw = Some(content.trim_end().to_string() + "\n");
                g.rules.push(r);
                Workspace {
                    groups: vec![g],
                    original: content.clone(),
                    on_server: true,
                    note: Some(match other {
                        Some(Err(e)) => format!("The saved rules couldn't be read ({e:#}), so the script was opened as raw Sieve."),
                        _ => format!("“{SCRIPT_NAME}” on the server wasn't made by this app, so it was opened as raw Sieve."),
                    }),
                }
            }
        }
    }

    fn compiled(&self) -> anyhow::Result<String> {
        rules::compile(&to_ruleset(&self.groups)?)
    }

    fn dirty(&self) -> bool {
        match self.compiled() {
            Ok(s) if self.on_server => s != self.original,
            Ok(_) => !self.groups.is_empty(),
            Err(_) => true,
        }
    }

    fn unique_name(&self, base: &str) -> String {
        let taken = |n: &str| self.groups.iter().any(|g| g.name.eq_ignore_ascii_case(n));
        if !taken(base) {
            return base.to_string();
        }
        (2..).map(|i| format!("{base} ({i})")).find(|n| !taken(n)).unwrap()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sel {
    Group(usize),
    Rule(usize, usize),
}

#[derive(Clone)]
enum After {
    LogOut,
    Quit,
}

struct ImportItem {
    name: String,
    active: bool,
    pick: bool,
}

enum Modal {
    Discard(After),
    /// Offer to bring the server's other scripts in as groups.
    Import(Vec<ImportItem>),
    /// After an import was saved: delete the scripts it came from?
    DeleteOld(Vec<String>),
    DeleteGroup(usize),
    /// Applying rules to messages already in the Inbox.
    Inbox { label: String, state: InboxState },
}

enum InboxState {
    Scanning,
    Preview(InboxView),
    Applying,
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Rules,
    Sieve,
    Server,
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
    ws: Option<Workspace>,
    sel: Option<Sel>,
    tab: Tab,
    modal: Option<Modal>,
    status: Option<(String, bool)>,
    check: Option<Result<Option<String>, String>>,
    /// The compiled script being uploaded.
    saving: Option<String>,
    /// IMAP folder list for the picker; None while loading or disconnected.
    folders: Option<Result<Vec<String>, String>>,
    /// Scripts imported into the workspace, offered for deletion after a save.
    imported: Vec<String>,
    /// Advanced: a server script opened read-only, and the one requested.
    server_view: Option<(String, String)>,
    viewing: Option<String>,
    allow_close: bool,
}

fn keyring_entry(s: &Settings) -> Option<keyring::Entry> {
    if s.user.trim().is_empty() || s.host.trim().is_empty() {
        return None;
    }
    sievectl::config::keychain_entry(&s.user, &s.host).ok()
}

/// Sidebar edits, applied after drawing so the loops can borrow freely.
enum Edit {
    AddGroup,
    MoveGroup(usize, isize),
    AddRule(usize, bool),
    MoveRule(usize, usize, isize),
    DeleteRule(usize, usize),
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
            ws: None,
            sel: None,
            tab: Tab::Rules,
            modal: None,
            status: None,
            check: None,
            saving: None,
            folders: None,
            imported: Vec::new(),
            server_view: None,
            viewing: None,
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

    fn active_script(&self) -> Option<&str> {
        self.scripts
            .iter()
            .find(|(_, a)| *a)
            .map(|(n, _)| n.as_str())
    }

    fn dirty(&self) -> bool {
        self.ws.as_ref().is_some_and(Workspace::dirty)
    }

    fn import_items(&self) -> Vec<ImportItem> {
        self.scripts
            .iter()
            .filter(|(n, _)| n != SCRIPT_NAME)
            .map(|(n, a)| ImportItem {
                name: n.clone(),
                active: *a,
                pick: true,
            })
            .collect()
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
            After::LogOut => {
                // Forget the saved password so the next launch shows the login form.
                if let Some(e) = keyring_entry(&self.s) {
                    let _ = e.delete_credential();
                }
                self.password.clear();
                self.ws = None;
                self.worker.send(Req::Disconnect);
            }
            After::Quit => {
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    /// Run `a` now, or ask first if there are unsaved changes.
    fn guard(&mut self, a: After, ctx: &egui::Context) {
        if self.dirty() {
            self.modal = Some(Modal::Discard(a));
        } else {
            self.after(a, ctx);
        }
    }

    /// CHECKSCRIPT, PUTSCRIPT "vera-colander", SETACTIVE "vera-colander".
    fn save(&mut self) {
        let Some(ws) = &self.ws else { return };
        match ws.compiled() {
            Ok(script) => {
                self.saving = Some(script.clone());
                self.worker.send(Req::Save {
                    name: SCRIPT_NAME.into(),
                    script,
                    activate: true,
                });
            }
            Err(e) => self.error(format!("Can't save: {e:#}")),
        }
    }

    /// Preview `rules` against the Inbox; the modal then offers to apply them.
    fn run_inbox(&mut self, rules: Vec<rules::Rule>, label: String) {
        self.modal = Some(Modal::Inbox {
            label,
            state: InboxState::Scanning,
        });
        self.worker.send(Req::InboxPreview(rules));
    }

    fn check(&mut self) {
        let Some(ws) = &self.ws else { return };
        match ws.compiled() {
            Ok(script) => self.worker.send(Req::Check(script)),
            Err(e) => self.check = Some(Err(format!("{e:#}"))),
        }
    }

    /// Add fetched scripts to the workspace as groups. Only the active one
    /// was running, so the others come in disabled.
    fn import(&mut self, fetched: Vec<(String, String)>) {
        let active = self.active_script().map(str::to_string);
        let ws = self.ws.get_or_insert_with(Workspace::empty);
        let first = ws.groups.len();
        let mut names = Vec::new();
        for (name, content) in fetched {
            if name == SCRIPT_NAME {
                continue;
            }
            let live = active.as_deref() == Some(name.as_str());
            for g in rules::import_script(&name, &content, live) {
                let mut ug = UiGroup::from_group(&g);
                ug.name = ws.unique_name(&ug.name);
                ws.groups.push(ug);
            }
            names.push(name);
        }
        if names.is_empty() {
            return;
        }
        ws.note = Some(format!(
            "Imported {} script{} as groups. Check them over, then Save to make them live.",
            names.len(),
            if names.len() == 1 { "" } else { "s" }
        ));
        self.sel = (first < ws.groups.len()).then_some(Sel::Group(first));
        self.tab = Tab::Rules;
        self.imported = names;
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
                self.scripts = scripts;
                if self.scripts.iter().any(|(n, _)| n == SCRIPT_NAME) {
                    self.worker.send(Req::Get(SCRIPT_NAME.into()));
                } else {
                    // First connect: start empty and offer the existing scripts.
                    self.ws = Some(Workspace::empty());
                    let items = self.import_items();
                    if !items.is_empty() {
                        self.modal = Some(Modal::Import(items));
                    }
                }
                self.folders = None;
                self.worker.send(Req::Folders);
            }
            Resp::Disconnected => {
                self.conn = None;
                self.folders = None;
                self.scripts.clear();
                self.ws = None;
                self.sel = None;
                self.server_view = None;
                self.imported.clear();
                self.info("Logged out");
            }
            Resp::Scripts { scripts, msg } => {
                self.scripts = scripts;
                if let Some(m) = msg {
                    self.info(m);
                }
            }
            Resp::Loaded { name, content } => {
                if self.viewing.as_deref() == Some(name.as_str()) {
                    self.viewing = None;
                    self.server_view = Some((name, content.replace("\r\n", "\n")));
                    self.tab = Tab::Server;
                } else if name == SCRIPT_NAME {
                    let ws = Workspace::from_script(&content);
                    self.sel = match ws.groups.first() {
                        Some(g) if !g.rules.is_empty() => Some(Sel::Rule(0, 0)),
                        Some(_) => Some(Sel::Group(0)),
                        None => None,
                    };
                    self.ws = Some(ws);
                    self.tab = Tab::Rules;
                    self.check = None;
                    self.status = None;
                }
            }
            Resp::LoadedMany(list) => self.import(list),
            Resp::Checked(r) => self.check = Some(r),
            Resp::Saved {
                name,
                warnings,
                scripts,
            } => {
                self.scripts = scripts;
                if name != SCRIPT_NAME {
                    return;
                }
                if let (Some(ws), Some(script)) = (&mut self.ws, self.saving.take()) {
                    ws.original = script;
                    ws.on_server = true;
                    ws.note = None;
                }
                self.check = warnings.clone().map(|w| Ok(Some(w)));
                self.info("Saved. Your rules are live.");
                if !self.imported.is_empty() {
                    self.modal = Some(Modal::DeleteOld(std::mem::take(&mut self.imported)));
                    return;
                }
                // Rules ticked "apply to the Inbox when I save".
                let mut run = Vec::new();
                if let Some(ws) = &mut self.ws {
                    for g in &mut ws.groups {
                        let live = g.enabled;
                        for r in g.rules.iter_mut().filter(|r| r.run_now) {
                            r.run_now = false;
                            if let (true, true, Ok(rule)) = (live, r.enabled, r.to_rule()) {
                                run.push(rule);
                            }
                        }
                    }
                }
                if !run.is_empty() {
                    let label = match run.as_slice() {
                        [one] => one.name.clone(),
                        many => format!("{} rules", many.len()),
                    };
                    self.run_inbox(run, label);
                }
            }
            Resp::Deleted { name, scripts } => {
                self.scripts = scripts;
                if self.server_view.as_ref().is_some_and(|(n, _)| *n == name) {
                    self.server_view = None;
                    self.tab = Tab::Rules;
                }
                self.info(format!("Deleted {name}"));
            }
            Resp::Folders(r) => self.folders = Some(r),
            Resp::InboxPreview(r) => {
                let inbox_open = matches!(self.modal, Some(Modal::Inbox { .. }));
                match r {
                    Ok(v) => {
                        if let Some(Modal::Inbox { state, .. }) = &mut self.modal {
                            *state = InboxState::Preview(v);
                        } else if self.modal.is_none() {
                            self.modal = Some(Modal::Inbox {
                                label: "Rules".into(),
                                state: InboxState::Preview(v),
                            });
                        }
                    }
                    Err(e) => {
                        if inbox_open {
                            self.modal = None;
                        }
                        self.error(format!("Couldn't check the Inbox: {e}"));
                    }
                }
            }
            Resp::InboxApplied(r) => {
                if matches!(self.modal, Some(Modal::Inbox { .. })) {
                    self.modal = None;
                }
                match r {
                    Ok(summary) => self.info(format!("Inbox: {summary}")),
                    Err(e) => self.error(format!("Couldn't finish applying the rule: {e}")),
                }
            }
            Resp::Error(e) => {
                self.connecting = false;
                self.auto_connecting = false;
                self.saving = None;
                self.viewing = None;
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

    fn sidebar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
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

        let mut edit: Option<Edit> = None;
        ui.horizontal(|ui| {
            ui.heading("Groups");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("➕").on_hover_text("New group").clicked() {
                    edit = Some(Edit::AddGroup);
                }
            });
        });
        ui.add_space(4.0);

        // Advanced pane takes the bottom; the group tree scrolls above it.
        let advanced = self.s.advanced;
        let mut open_script: Option<String> = None;
        let mut refresh = false;
        egui::Panel::bottom("advanced")
            .resizable(false)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.checkbox(&mut self.s.advanced, "Advanced")
                    .on_hover_text("Show the raw scripts on the server, for debugging");
                if advanced {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Server scripts").strong());
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            refresh = ui.small_button("🔄").on_hover_text("Refresh").clicked();
                        });
                    });
                    let open = self.server_view.as_ref().map(|(n, _)| n.as_str());
                    for (name, active) in &self.scripts {
                        let text = if *active {
                            RichText::new(format!("★ {name}")).strong()
                        } else {
                            RichText::new(format!("    {name}"))
                        };
                        if ui
                            .selectable_label(open == Some(name.as_str()), text)
                            .on_hover_text("Open read-only")
                            .clicked()
                        {
                            open_script = Some(name.clone());
                        }
                    }
                    ui.label(RichText::new("★ = active. Read-only view.").weak().small());
                }
                ui.add_space(4.0);
            });
        if refresh {
            self.worker.send(Req::List);
        }
        if let Some(n) = open_script {
            self.viewing = Some(n.clone());
            self.worker.send(Req::Get(n));
        }

        let Some(ws) = &mut self.ws else {
            return;
        };
        let sel = &mut self.sel;
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let ng = ws.groups.len();
                for (gi, g) in ws.groups.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        let arrow = if g.collapsed { "▶" } else { "▼" };
                        if ui.small_button(arrow).on_hover_text("Show/hide rules").clicked() {
                            g.collapsed = !g.collapsed;
                        }
                        ui.checkbox(&mut g.enabled, "")
                            .on_hover_text("Enable or disable the whole group");
                        let mut t = RichText::new(if g.name.trim().is_empty() {
                            "(unnamed)"
                        } else {
                            g.name.as_str()
                        })
                        .strong();
                        if !g.enabled {
                            t = t.weak().strikethrough();
                        }
                        if ui.selectable_label(*sel == Some(Sel::Group(gi)), t).clicked() {
                            *sel = Some(Sel::Group(gi));
                        }
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(gi + 1 < ng, egui::Button::new("⬇").small())
                                .on_hover_text("Move group down")
                                .clicked()
                            {
                                edit = Some(Edit::MoveGroup(gi, 1));
                            }
                            if ui
                                .add_enabled(gi > 0, egui::Button::new("⬆").small())
                                .on_hover_text("Move group up")
                                .clicked()
                            {
                                edit = Some(Edit::MoveGroup(gi, -1));
                            }
                        });
                    });
                    if g.collapsed {
                        continue;
                    }
                    let nr = g.rules.len();
                    ui.indent(("group", gi), |ui| {
                        for (ri, r) in g.rules.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut r.enabled, "").on_hover_text("Enabled");
                                let name = if r.name.trim().is_empty() {
                                    "(unnamed)".to_string()
                                } else if r.raw.is_some() {
                                    format!("⌨ {}", r.name)
                                } else {
                                    r.name.clone()
                                };
                                let mut t = RichText::new(name);
                                if !r.enabled || !g.enabled {
                                    t = t.weak();
                                }
                                if !r.enabled {
                                    t = t.strikethrough();
                                }
                                if ui
                                    .selectable_label(*sel == Some(Sel::Rule(gi, ri)), t)
                                    .clicked()
                                {
                                    *sel = Some(Sel::Rule(gi, ri));
                                }
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button("🗑").on_hover_text("Delete rule").clicked() {
                                        edit = Some(Edit::DeleteRule(gi, ri));
                                    }
                                    if ui
                                        .add_enabled(ri + 1 < nr, egui::Button::new("⬇").small())
                                        .clicked()
                                    {
                                        edit = Some(Edit::MoveRule(gi, ri, 1));
                                    }
                                    if ui
                                        .add_enabled(ri > 0, egui::Button::new("⬆").small())
                                        .clicked()
                                    {
                                        edit = Some(Edit::MoveRule(gi, ri, -1));
                                    }
                                });
                            });
                        }
                        ui.horizontal(|ui| {
                            if ui.small_button("➕ Rule").clicked() {
                                edit = Some(Edit::AddRule(gi, false));
                            }
                            if ui
                                .small_button("➕ Raw Sieve")
                                .on_hover_text("A block of hand-written Sieve, inserted as-is")
                                .clicked()
                            {
                                edit = Some(Edit::AddRule(gi, true));
                            }
                        });
                    });
                    ui.add_space(4.0);
                }
                if ws.groups.is_empty() {
                    ui.label(RichText::new("No groups yet. Add one with ➕.").weak());
                }
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Groups and rules run top to bottom.")
                        .weak()
                        .small(),
                );
            });

        match edit {
            Some(Edit::AddGroup) => {
                let name = ws.unique_name("New group");
                ws.groups.push(UiGroup::new(name));
                *sel = Some(Sel::Group(ws.groups.len() - 1));
            }
            Some(Edit::MoveGroup(gi, d)) => {
                let gj = (gi as isize + d) as usize;
                ws.groups.swap(gi, gj);
                *sel = sel.map(|s| match s {
                    Sel::Group(x) if x == gi => Sel::Group(gj),
                    Sel::Group(x) if x == gj => Sel::Group(gi),
                    Sel::Rule(x, r) if x == gi => Sel::Rule(gj, r),
                    Sel::Rule(x, r) if x == gj => Sel::Rule(gi, r),
                    s => s,
                });
            }
            Some(Edit::AddRule(gi, raw)) => {
                let g = &mut ws.groups[gi];
                let n = g.rules.len() + 1;
                g.rules.push(if raw { UiRule::new_raw(n) } else { UiRule::new(n) });
                g.collapsed = false;
                *sel = Some(Sel::Rule(gi, g.rules.len() - 1));
            }
            Some(Edit::MoveRule(gi, ri, d)) => {
                let rj = (ri as isize + d) as usize;
                ws.groups[gi].rules.swap(ri, rj);
                if *sel == Some(Sel::Rule(gi, ri)) {
                    *sel = Some(Sel::Rule(gi, rj));
                } else if *sel == Some(Sel::Rule(gi, rj)) {
                    *sel = Some(Sel::Rule(gi, ri));
                }
            }
            Some(Edit::DeleteRule(gi, ri)) => {
                ws.groups[gi].rules.remove(ri);
                if matches!(*sel, Some(Sel::Rule(g, _)) if g == gi) {
                    *sel = Some(Sel::Group(gi));
                }
            }
            None => {}
        }
    }

    fn main_view(&mut self, ui: &mut egui::Ui) {
        let Some(ws) = &self.ws else {
            ui.centered_and_justified(|ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Loading your rules…");
                });
            });
            return;
        };
        let dirty = ws.dirty();
        let on_server = ws.on_server;
        let compiled = ws.compiled();
        let note = ws.note.clone();
        let active = self.active_script().map(str::to_string);
        let live = on_server && active.as_deref() == Some(SCRIPT_NAME);

        // toolbar
        let mut act: Option<&str> = None;
        ui.horizontal(|ui| {
            ui.heading("Your rules");
            if dirty {
                ui.label(RichText::new("• unsaved").color(ui.visuals().warn_fg_color));
            } else if live {
                ui.label(RichText::new("● live").color(Color32::from_rgb(0x3f, 0xa3, 0x4d)))
                    .on_hover_text(format!("Saved and active on the server as “{SCRIPT_NAME}”"));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.menu_button("More…", |ui| {
                    if ui.button("Import server scripts…").clicked() {
                        act = Some("import");
                        ui.close();
                    }
                });
                let save = ui.add_enabled(dirty, egui::Button::new("💾 Save"));
                if save
                    .on_hover_text(format!(
                        "Validate, upload and activate “{SCRIPT_NAME}” ({})",
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
            Some("save") => self.save(),
            Some("check") => self.check(),
            Some("revert") => self.worker.send(Req::Get(SCRIPT_NAME.into())),
            Some("import") => {
                let items = self.import_items();
                if items.is_empty() {
                    self.info("There are no other scripts on the server.");
                } else {
                    self.modal = Some(Modal::Import(items));
                }
            }
            _ => {}
        }

        // banners
        if on_server && !live {
            let text = match &active {
                Some(n) => format!("Another app activated “{n}”. Your rules aren't running."),
                None => "No script is active on the server. Your rules aren't running.".into(),
            };
            egui::Frame::group(ui.style())
                .fill(ui.visuals().warn_fg_color.gamma_multiply(0.12))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {text}"));
                        if ui
                            .button("Take over")
                            .on_hover_text(format!("Make “{SCRIPT_NAME}” the active script again"))
                            .clicked()
                        {
                            self.worker.send(Req::Activate(SCRIPT_NAME.into()));
                        }
                    });
                });
        }
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

        let mut close_server = false;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Rules, "Rules");
            ui.selectable_value(&mut self.tab, Tab::Sieve, "Generated Sieve");
            if let Some((n, _)) = &self.server_view {
                ui.selectable_value(&mut self.tab, Tab::Server, format!("Server: {n}"));
                close_server = ui.small_button("✖").on_hover_text("Close").clicked();
            }
        });
        if close_server {
            self.server_view = None;
            if self.tab == Tab::Server {
                self.tab = Tab::Rules;
            }
        }
        ui.separator();

        match self.tab {
            Tab::Rules => self.rules_view(ui),
            Tab::Sieve => read_only_code(
                ui,
                compiled.map_err(|e| format!("{e:#}")),
                "Read-only: the whole script, generated from all groups. The #@ block at the end stores the groups and rules so they can be reopened.",
            ),
            Tab::Server => match &self.server_view {
                Some((n, text)) => read_only_code(
                    ui,
                    Ok(text.clone()),
                    &format!("Read-only copy of “{n}” as stored on the server."),
                ),
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading…");
                    });
                }
            },
        }
    }

    fn rules_view(&mut self, ui: &mut egui::Ui) {
        let Some(ws) = &mut self.ws else { return };
        // Drop a selection that no longer exists.
        self.sel = match self.sel {
            Some(Sel::Rule(g, r)) if ws.groups.get(g).is_some_and(|x| r < x.rules.len()) => {
                Some(Sel::Rule(g, r))
            }
            Some(Sel::Rule(g, _)) | Some(Sel::Group(g)) if g < ws.groups.len() => {
                Some(Sel::Group(g))
            }
            _ => None,
        };
        let folders = self.folders.as_ref();
        let mut reload = false;
        let mut run = false;
        let mut move_to: Option<usize> = None;
        let mut delete_group = false;
        let group_names: Vec<String> = ws.groups.iter().map(|g| g.name.clone()).collect();

        match self.sel {
            Some(Sel::Rule(gi, ri)) => {
                let rule = &mut ws.groups[gi].rules[ri];
                if rule.raw.is_none() {
                    let preview = rule
                        .to_rule()
                        .and_then(|r| rules::compile_rule(&r, &mut Default::default()));
                    egui::Panel::bottom("rule_preview")
                        .resizable(true)
                        .default_size(180.0)
                        .show(ui, |ui| {
                            ui.add_space(4.0);
                            ui.label(RichText::new("Sieve for this rule").strong());
                            match preview {
                                Ok(s) => {
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
                                    ui.colored_label(
                                        ui.visuals().error_fg_color,
                                        format!("⚠ {e:#}"),
                                    );
                                }
                            }
                        });
                }
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Group");
                            let mut target = gi;
                            ComboBox::from_id_salt(("rule_group", gi, ri))
                                .selected_text(group_names[gi].as_str())
                                .show_ui(ui, |ui| {
                                    for (i, n) in group_names.iter().enumerate() {
                                        ui.selectable_value(&mut target, i, n.as_str());
                                    }
                                });
                            if target != gi {
                                move_to = Some(target);
                            }
                        });
                        let uid = gi * 1000 + ri;
                        if rule.raw.is_some() {
                            raw_editor(ui, rule);
                        } else {
                            rule_editor(ui, rule, uid, folders, &mut reload, &mut run);
                        }
                    });
            }
            Some(Sel::Group(gi)) => {
                let g = &mut ws.groups[gi];
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Group name");
                            ui.add(TextEdit::singleline(&mut g.name).desired_width(320.0));
                            ui.checkbox(&mut g.enabled, "Enabled");
                        });
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(format!(
                                "{} rule{}. {}",
                                g.rules.len(),
                                if g.rules.len() == 1 { "" } else { "s" },
                                if g.enabled {
                                    "Its rules run in order, after the groups above it."
                                } else {
                                    "Disabled: none of its rules are in the script."
                                }
                            ))
                            .weak(),
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("➕ Add rule").clicked() {
                                g.rules.push(UiRule::new(g.rules.len() + 1));
                                g.collapsed = false;
                                self.sel = Some(Sel::Rule(gi, g.rules.len() - 1));
                            }
                            if ui.button("➕ Add raw Sieve").clicked() {
                                g.rules.push(UiRule::new_raw(g.rules.len() + 1));
                                g.collapsed = false;
                                self.sel = Some(Sel::Rule(gi, g.rules.len() - 1));
                            }
                        });
                        ui.add_space(16.0);
                        if ui
                            .button(
                                RichText::new("🗑 Delete group…")
                                    .color(ui.visuals().error_fg_color),
                            )
                            .clicked()
                        {
                            delete_group = true;
                        }
                    });
                if delete_group {
                    self.modal = Some(Modal::DeleteGroup(gi));
                }
            }
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new(if ws.groups.is_empty() {
                            "Add a group with ➕ on the left, then add rules to it."
                        } else {
                            "Select a group or rule on the left."
                        })
                        .weak(),
                    );
                });
            }
        }

        if let (Some(target), Some(Sel::Rule(gi, ri))) = (move_to, self.sel) {
            let r = ws.groups[gi].rules.remove(ri);
            ws.groups[target].rules.push(r);
            ws.groups[target].collapsed = false;
            self.sel = Some(Sel::Rule(target, ws.groups[target].rules.len() - 1));
        }
        if reload {
            self.folders = None;
            self.worker.send(Req::Folders);
        }
        if run {
            let picked = match (self.sel, &self.ws) {
                (Some(Sel::Rule(gi, ri)), Some(ws)) => ws.groups[gi]
                    .rules
                    .get(ri)
                    .map(|r| (r.name.clone(), r.to_rule())),
                _ => None,
            };
            match picked {
                Some((name, Ok(rule))) => self.run_inbox(vec![rule], name),
                Some((_, Err(e))) => self.error(format!("Fix the rule first: {e:#}")),
                None => {}
            }
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
        let resp = egui::Modal::new(egui::Id::new("modal")).show(ctx, |ui| {
            ui.set_width(380.0);
            match &mut m {
                Modal::Discard(a) => {
                    ui.heading("Unsaved changes");
                    ui.label("Your rules have changes that aren't on the server yet. Discard them?");
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
                Modal::Import(items) => {
                    ui.set_width(460.0);
                    ui.heading("Bring in your existing filters?");
                    ui.add_space(4.0);
                    ui.label(format!(
                        "Vera Colander keeps all your rules in one script, “{SCRIPT_NAME}”, and keeps it active. These scripts are on the server now. Import them as groups:"
                    ));
                    ui.add_space(6.0);
                    for it in items.iter_mut() {
                        let label = if it.active {
                            format!("{} (active)", it.name)
                        } else {
                            it.name.clone()
                        };
                        ui.checkbox(&mut it.pick, label);
                    }
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Only the active script was running, so the others come in as disabled groups. Nothing changes on the server until you Save.")
                            .weak()
                            .small(),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let any = items.iter().any(|i| i.pick);
                        if ui.add_enabled(any, egui::Button::new("Import")).clicked() {
                            // Active script first: it's the one that was running.
                            let mut names: Vec<(bool, String)> = items
                                .iter()
                                .filter(|i| i.pick)
                                .map(|i| (!i.active, i.name.clone()))
                                .collect();
                            names.sort_by_key(|(inactive, _)| *inactive);
                            self.worker
                                .send(Req::GetMany(names.into_iter().map(|(_, n)| n).collect()));
                            keep = false;
                        }
                        if ui.button("Start fresh").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::DeleteOld(names) => {
                    ui.set_width(440.0);
                    ui.heading("Delete the old scripts?");
                    ui.label(format!(
                        "Your rules are now saved in “{SCRIPT_NAME}”, which is the active script. These old scripts aren't used any more:"
                    ));
                    for n in names.iter() {
                        ui.label(format!("  • {n}"));
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .button(RichText::new("Delete them").color(ui.visuals().error_fg_color))
                            .clicked()
                        {
                            for n in names.iter() {
                                self.worker.send(Req::Delete(n.clone()));
                            }
                            keep = false;
                        }
                        if ui.button("Keep them").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::DeleteGroup(gi) => {
                    let gi = *gi;
                    let (name, n) = self
                        .ws
                        .as_ref()
                        .and_then(|w| w.groups.get(gi))
                        .map(|g| (g.name.clone(), g.rules.len()))
                        .unwrap_or_default();
                    ui.heading(format!("Delete group “{name}”?"));
                    ui.label(format!(
                        "The group and its {n} rule{} are removed when you next Save.",
                        if n == 1 { "" } else { "s" }
                    ));
                    ui.horizontal(|ui| {
                        if ui
                            .button(RichText::new("Delete").color(ui.visuals().error_fg_color))
                            .clicked()
                        {
                            if let Some(ws) = &mut self.ws {
                                if gi < ws.groups.len() {
                                    ws.groups.remove(gi);
                                }
                            }
                            self.sel = None;
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                }
                Modal::Inbox { label, state } => match state {
                    InboxState::Scanning => {
                        ui.heading(format!("Checking the Inbox for “{label}”"));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Reading messages…");
                        });
                    }
                    InboxState::Applying => {
                        ui.heading(format!("Applying “{label}”"));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Working…");
                        });
                    }
                    InboxState::Preview(v) => {
                        ui.set_width(760.0);
                        ui.heading(format!("Apply “{label}” to the Inbox"));
                        ui.label(format!(
                            "{} of {} Inbox messages would change.",
                            v.rows.len(),
                            v.scanned
                        ));
                        for n in &v.notes {
                            ui.colored_label(ui.visuals().warn_fg_color, format!("⚠ {n}"));
                        }
                        if !v.rows.is_empty() {
                            ui.add_space(6.0);
                            let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
                            ScrollArea::vertical()
                                .max_height(360.0)
                                .auto_shrink([false, true])
                                .show_rows(ui, row_h, v.rows.len(), |ui, range| {
                                    egui::Grid::new("inbox_rows")
                                        .striped(true)
                                        .num_columns(4)
                                        .min_row_height(row_h)
                                        .show(ui, |ui| {
                                            for r in &v.rows[range] {
                                                ui.label(RichText::new(&r.date).weak());
                                                ui.add(egui::Label::new(&r.from).truncate())
                                                    .on_hover_text(&r.from);
                                                ui.add_sized(
                                                    [300.0, row_h],
                                                    egui::Label::new(&r.subject).truncate(),
                                                )
                                                .on_hover_text(&r.subject);
                                                ui.label(RichText::new(&r.outcome).strong());
                                                ui.end_row();
                                            }
                                        });
                                });
                        }
                        ui.add_space(8.0);
                        let mut apply = false;
                        ui.horizontal(|ui| {
                            let n = v.rows.len();
                            if n > 0
                                && ui
                                    .button(format!(
                                        "Apply to {n} message{}",
                                        if n == 1 { "" } else { "s" }
                                    ))
                                    .clicked()
                            {
                                apply = true;
                            }
                            if ui.button(if n > 0 { "Cancel" } else { "Close" }).clicked() {
                                keep = false;
                            }
                        });
                        if apply {
                            self.worker.send(Req::InboxApply);
                            *state = InboxState::Applying;
                        }
                    }
                },
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
            self.save();
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.conn.is_none() {
            egui::CentralPanel::default().show(ui, |ui| self.connect_view(ui));
        } else {
            egui::Panel::left("groups")
                .resizable(true)
                .default_size(260.0)
                .show(ui, |ui| self.sidebar(ui, &ctx));
            egui::CentralPanel::default().show(ui, |ui| self.main_view(ui));
        }
        self.modals(&ctx);
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.s);
    }
}

fn read_only_code(ui: &mut egui::Ui, text: Result<String, String>, hint: &str) {
    match text {
        Ok(s) => {
            ui.label(RichText::new(hint).weak().small());
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
            ui.colored_label(ui.visuals().error_fg_color, format!("⚠ {e}"));
        }
    }
}

/// Editor for a hand-written Sieve block.
fn raw_editor(ui: &mut egui::Ui, r: &mut UiRule) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Name");
        ui.add(TextEdit::singleline(&mut r.name).desired_width(320.0));
        ui.checkbox(&mut r.enabled, "Enabled");
    });
    section(ui, "Raw Sieve");
    ui.label(
        RichText::new("Inserted into the script exactly as written, at this position. Any require lines are moved into the single require at the top.")
            .weak(),
    );
    ui.add_space(4.0);
    if let Some(text) = &mut r.raw {
        ui.add(
            TextEdit::multiline(text)
                .code_editor()
                .desired_rows(18)
                .desired_width(f32::INFINITY),
        );
    }
}

fn tls_label(t: TlsMode) -> &'static str {
    match t {
        TlsMode::Starttls => "STARTTLS (port 4190, standard)",
        TlsMode::Implicit => "TLS from the start",
        TlsMode::None => "None (unencrypted)",
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
    run: &mut bool,
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

    section(ui, "Mail already in the Inbox");
    ui.label(
        RichText::new("Filters only run on new mail. These apply the rule to what's already there.")
            .weak(),
    );
    ui.checkbox(&mut r.run_now, "Apply to the Inbox when I save")
        .on_hover_text("After the next Save, preview the matching Inbox messages and confirm");
    if ui
        .button("▶ Run on Inbox now…")
        .on_hover_text("Preview which Inbox messages this rule matches, then apply it")
        .clicked()
    {
        *run = true;
    }
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
