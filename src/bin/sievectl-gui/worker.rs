//! Background thread that owns the ManageSieve connection. The UI sends one
//! `Req`, the worker answers with exactly one `Resp` and requests a repaint.

use sievectl::inbox::{self, Account, Plan, Row};
use sievectl::managesieve::{Capabilities, Client, ConnectOptions};
use sievectl::rules::Rule;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

pub type Scripts = Vec<(String, bool)>;

pub enum Req {
    Connect {
        opts: ConnectOptions,
        user: String,
        pass: String,
    },
    Disconnect,
    List,
    Get(String),
    /// Several scripts at once, for importing them as groups.
    GetMany(Vec<String>),
    Check(String),
    Save {
        name: String,
        script: String,
        activate: bool,
    },
    Activate(String),
    Delete(String),
    /// Mail folders over IMAP (implicit TLS on 993), for the folder picker.
    Folders,
    /// Work out what these rules would do to messages already in the Inbox.
    InboxPreview(Vec<Rule>),
    /// Carry out the last preview.
    InboxApply,
}

pub struct InboxView {
    pub scanned: usize,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
}

pub enum Resp {
    Connected {
        caps: Capabilities,
        scripts: Scripts,
    },
    Disconnected,
    Scripts {
        scripts: Scripts,
        msg: Option<String>,
    },
    Loaded {
        name: String,
        content: String,
    },
    LoadedMany(Vec<(String, String)>),
    Checked(Result<Option<String>, String>),
    Saved {
        name: String,
        warnings: Option<String>,
        scripts: Scripts,
    },
    Deleted {
        name: String,
        scripts: Scripts,
    },
    /// Separate from `Error`: a failed folder list shouldn't flag the session.
    Folders(Result<Vec<String>, String>),
    InboxPreview(Result<InboxView, String>),
    InboxApplied(Result<String, String>),
    Error(String),
}

pub struct Worker {
    tx: Sender<Req>,
    rx: Receiver<Resp>,
    pub pending: usize,
}

impl Worker {
    pub fn spawn(ctx: egui::Context) -> Worker {
        let (tx, req_rx) = channel::<Req>();
        let (resp_tx, rx) = channel::<Resp>();
        thread::Builder::new()
            .name("managesieve".into())
            .spawn(move || {
                let mut st = State::default();
                for req in req_rx {
                    let resp = st.handle(req);
                    if resp_tx.send(resp).is_err() {
                        break;
                    }
                    ctx.request_repaint();
                }
                if let Some(c) = st.client.take() {
                    c.logout();
                }
            })
            .expect("spawn worker");
        Worker { tx, rx, pending: 0 }
    }

    pub fn send(&mut self, r: Req) {
        if self.tx.send(r).is_ok() {
            self.pending += 1;
        }
    }

    pub fn poll(&mut self) -> Vec<Resp> {
        let v: Vec<Resp> = self.rx.try_iter().collect();
        self.pending = self.pending.saturating_sub(v.len());
        v
    }

    pub fn busy(&self) -> bool {
        self.pending > 0
    }
}

#[derive(Default)]
struct State {
    client: Option<Client>,
    creds: Option<(ConnectOptions, String, String)>,
    plan: Option<Plan>,
}

fn is_connection_error(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<std::io::Error>()) || e.to_string().contains("closed the connection")
}

impl State {
    fn account(&self) -> anyhow::Result<Account> {
        let (opts, user, pass) = self
            .creds
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;
        Ok(Account {
            host: opts.host.clone(),
            ca_file: opts.ca_file.clone(),
            user: user.clone(),
            pass: pass.clone(),
            imap_port: 993,
            smtp_port: 465,
        })
    }

    fn open(&mut self) -> anyhow::Result<()> {
        let (opts, user, pass) = self
            .creds
            .clone()
            .ok_or_else(|| anyhow::anyhow!("not connected"))?;
        let mut c = Client::connect(&opts)?;
        if !c.tls_active && opts.tls != sievectl::managesieve::TlsMode::None {
            anyhow::bail!("TLS was not negotiated");
        }
        c.authenticate_plain(&user, &pass)?;
        self.client = Some(c);
        Ok(())
    }

    /// Run `f` on the connection, reconnecting once if the server dropped us
    /// (idle timeouts are common).
    fn with<T>(
        &mut self,
        mut f: impl FnMut(&mut Client) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if self.client.is_none() {
            self.open()?;
        }
        match f(self.client.as_mut().unwrap()) {
            Err(e) if is_connection_error(&e) => {
                self.client = None;
                self.open()?;
                f(self.client.as_mut().unwrap())
            }
            r => r,
        }
    }

    fn handle(&mut self, req: Req) -> Resp {
        let r: anyhow::Result<Resp> = (|| match req {
            Req::Connect { opts, user, pass } => {
                if let Some(c) = self.client.take() {
                    c.logout();
                }
                self.creds = Some((opts, user, pass));
                if let Err(e) = self.open() {
                    self.creds = None;
                    return Err(e);
                }
                let c = self.client.as_mut().unwrap();
                let scripts = c.list_scripts()?;
                Ok(Resp::Connected {
                    caps: c.caps.clone(),
                    scripts,
                })
            }
            Req::Disconnect => {
                if let Some(c) = self.client.take() {
                    c.logout();
                }
                self.creds = None;
                Ok(Resp::Disconnected)
            }
            Req::List => Ok(Resp::Scripts {
                scripts: self.with(|c| c.list_scripts())?,
                msg: None,
            }),
            Req::Get(name) => {
                let content = self.with(|c| c.get_script(&name))?;
                Ok(Resp::Loaded { name, content })
            }
            Req::GetMany(names) => {
                let mut out = Vec::new();
                for n in names {
                    let content = self.with(|c| c.get_script(&n))?;
                    out.push((n, content));
                }
                Ok(Resp::LoadedMany(out))
            }
            Req::Check(script) => {
                let r = self.with(|c| match c.check_script(&script) {
                    Ok(w) => Ok(Ok(w)),
                    Err(e) if is_connection_error(&e) => Err(e),
                    Err(e) => Ok(Err(format!("{e:#}"))),
                })?;
                Ok(Resp::Checked(r))
            }
            Req::Save {
                name,
                script,
                activate,
            } => {
                let (warnings, scripts) = self.with(|c| {
                    let w = c.check_script(&script)?;
                    let w2 = c.put_script(&name, &script)?;
                    if activate {
                        c.set_active(&name)?;
                    }
                    Ok((w.or(w2), c.list_scripts()?))
                })?;
                Ok(Resp::Saved {
                    name,
                    warnings,
                    scripts,
                })
            }
            Req::Activate(name) => {
                let scripts = self.with(|c| {
                    c.set_active(&name)?;
                    c.list_scripts()
                })?;
                let msg = if name.is_empty() {
                    "All scripts deactivated".to_string()
                } else {
                    format!("{name} is now active")
                };
                Ok(Resp::Scripts {
                    scripts,
                    msg: Some(msg),
                })
            }
            Req::Delete(name) => {
                let scripts = self.with(|c| {
                    c.delete_script(&name)?;
                    c.list_scripts()
                })?;
                Ok(Resp::Deleted { name, scripts })
            }
            Req::Folders => {
                let a = self.account()?;
                let r = sievectl::imap::list_folders(
                    &a.host,
                    a.imap_port,
                    a.ca_file.as_deref(),
                    &a.user,
                    &a.pass,
                );
                Ok(Resp::Folders(r.map_err(|e| format!("{e:#}"))))
            }
            Req::InboxPreview(rules) => {
                self.plan = None;
                let r = inbox::preview(&self.account()?, &rules).map(|p| {
                    self.plan = Some(p.plan);
                    InboxView {
                        scanned: p.scanned,
                        rows: p.rows,
                        notes: p.notes,
                    }
                });
                Ok(Resp::InboxPreview(r.map_err(|e| format!("{e:#}"))))
            }
            Req::InboxApply => {
                let plan = self
                    .plan
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("nothing to apply"))?;
                let r = inbox::apply(&self.account()?, &plan);
                Ok(Resp::InboxApplied(r.map_err(|e| format!("{e:#}"))))
            }
        })();
        r.unwrap_or_else(|e| Resp::Error(format!("{e:#}")))
    }
}
