//! Apply rules to messages already in the Inbox. Sieve only runs at delivery,
//! so this evaluates the rules locally against each message (fetched over
//! IMAP) with Sieve's matching semantics, shows what would happen, and then
//! carries it out with IMAP (move/copy/flag) and SMTP (forward).

use crate::imap::{Fetched, Session};
use crate::rules::{classify, Action, Condition, FieldKind, MatchKind, Op, Rule};
use crate::smtp::Submission;
use anyhow::{bail, Context, Result};
use mail_parser::{parsers::MessageStream, MessageParser};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const INBOX: &str = "INBOX";

#[derive(Clone)]
pub struct Account {
    pub host: String,
    pub ca_file: Option<PathBuf>,
    pub user: String,
    pub pass: String,
    pub imap_port: u16,
    pub smtp_port: u16,
}

impl Account {
    fn imap(&self) -> Result<Session> {
        Session::login(
            &self.host,
            self.imap_port,
            self.ca_file.as_deref(),
            &self.user,
            &self.pass,
        )
        .with_context(|| format!("IMAP {}:{}", self.host, self.imap_port))
    }
}

/// One Inbox message that the rules would change, for the preview.
pub struct Row {
    pub from: String,
    pub subject: String,
    pub date: String,
    pub outcome: String,
}

pub struct Preview {
    pub scanned: usize,
    pub rows: Vec<Row>,
    /// Things the user should know: skipped actions, missing folders…
    pub notes: Vec<String>,
    pub plan: Plan,
}

/// What to do, ready for `apply`. Kept out of the UI.
pub struct Plan {
    uidvalidity: u32,
    create: BTreeSet<String>,
    msgs: Vec<MsgPlan>,
}

#[derive(Default)]
struct MsgPlan {
    uid: u32,
    flags: Vec<String>,
    copies: Vec<String>,
    move_to: Option<String>,
    forwards: Vec<String>,
}

impl MsgPlan {
    fn is_noop(&self) -> bool {
        self.flags.is_empty()
            && self.copies.is_empty()
            && self.move_to.is_none()
            && self.forwards.is_empty()
    }
}

/// Scan the Inbox and work out what `rules` (in order) would do to each
/// message. Nothing is changed.
pub fn preview(acct: &Account, rules: &[Rule]) -> Result<Preview> {
    let matchers: Vec<CompiledRule> = rules.iter().map(CompiledRule::new).collect::<Result<_>>()?;
    let needs_body = matchers.iter().any(|r| r.needs_body);

    let mut imap = acct.imap()?;
    let folders = imap.list()?;
    let trash = folders
        .iter()
        .find(|f| f.trash)
        .or_else(|| {
            folders.iter().find(|f| {
                ["Trash", "Deleted Items", "Deleted Messages"]
                    .iter()
                    .any(|n| f.name.eq_ignore_ascii_case(n))
            })
        })
        .map(|f| f.name.clone());
    let exists: BTreeSet<String> = folders.into_iter().map(|f| f.name).collect();
    let uidvalidity = imap.examine(INBOX)?;
    let fetched = imap.fetch_all(needs_body)?;
    imap.logout();

    let parser = MessageParser::default();
    let mut notes = BTreeSet::new();
    let mut create = BTreeSet::new();
    let mut rows = Vec::new();
    let mut msgs = Vec::new();
    for f in &fetched {
        let Some(m) = Msg::parse(&parser, f, needs_body) else {
            continue;
        };
        let p = plan_message(&matchers, &m, &exists, trash.as_deref(), &mut create, &mut notes);
        if p.is_noop() {
            continue;
        }
        rows.push(Row {
            from: m.from_display.clone(),
            subject: m.subject.clone(),
            date: m.date.clone(),
            outcome: describe(&p),
        });
        msgs.push(p);
    }
    Ok(Preview {
        scanned: fetched.len(),
        rows,
        notes: notes.into_iter().collect(),
        plan: Plan {
            uidvalidity,
            create,
            msgs,
        },
    })
}

/// Carry out a plan from `preview`. Returns a one-line summary.
pub fn apply(acct: &Account, plan: &Plan) -> Result<String> {
    let mut imap = acct.imap()?;
    for f in &plan.create {
        imap.create(f)?;
    }
    if imap.select(INBOX)? != plan.uidvalidity {
        bail!("the Inbox changed on the server since the preview; run it again");
    }

    // Forward first: if sending fails, nothing has been moved yet.
    let mut forwarded = 0;
    let fwd_uids: Vec<u32> = plan
        .msgs
        .iter()
        .filter(|m| !m.forwards.is_empty())
        .map(|m| m.uid)
        .collect();
    if !fwd_uids.is_empty() {
        let full = imap.fetch_full(&fwd_uids)?;
        let mut smtp = Submission::login(
            &acct.host,
            acct.smtp_port,
            acct.ca_file.as_deref(),
            &acct.user,
            &acct.pass,
        )
        .with_context(|| format!("SMTP {}:{}", acct.host, acct.smtp_port))?;
        for m in plan.msgs.iter().filter(|m| !m.forwards.is_empty()) {
            let Some(raw) = full.iter().find(|f| f.uid == m.uid) else {
                continue;
            };
            for to in &m.forwards {
                smtp.redirect(&acct.user, to, &raw.data)
                    .with_context(|| format!("forwarding to {to} (after {forwarded} sent)"))?;
                forwarded += 1;
            }
        }
        smtp.quit();
    }

    let mut by_flags: BTreeMap<Vec<String>, Vec<u32>> = BTreeMap::new();
    let mut copies: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    let mut moves: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for m in &plan.msgs {
        if !m.flags.is_empty() {
            by_flags.entry(m.flags.clone()).or_default().push(m.uid);
        }
        for c in &m.copies {
            copies.entry(c).or_default().push(m.uid);
        }
        if let Some(t) = &m.move_to {
            moves.entry(t).or_default().push(m.uid);
        }
    }
    // Flags before copy/move so the copies carry them, as imap4flags would.
    let mut flagged = 0;
    for (flags, uids) in &by_flags {
        imap.add_flags(uids, flags)?;
        flagged += uids.len();
    }
    let mut copied = 0;
    for (folder, uids) in &copies {
        imap.copy(uids, folder)?;
        copied += uids.len();
    }
    let mut moved = Vec::new();
    for (folder, uids) in &moves {
        imap.move_to(uids, folder)?;
        moved.push(format!("{} to {folder}", count(uids.len())));
    }
    imap.logout();

    let mut parts = Vec::new();
    if !moved.is_empty() {
        parts.push(format!("moved {}", moved.join(", ")));
    }
    if copied > 0 {
        parts.push(format!("copied {}", count(copied)));
    }
    if flagged > 0 {
        parts.push(format!("flagged {}", count(flagged)));
    }
    if forwarded > 0 {
        parts.push(format!("forwarded {}", count(forwarded)));
    }
    let s = parts.join("; ");
    Ok(if s.is_empty() {
        "Nothing to do".into()
    } else {
        let mut c = s.chars();
        c.next().unwrap().to_uppercase().chain(c).collect()
    })
}

fn count(n: usize) -> String {
    if n == 1 {
        "1 message".into()
    } else {
        format!("{n} messages")
    }
}

// ---------------------------------------------------------------------------
// Per-message plan: a small Sieve interpreter over the rule model.

fn plan_message(
    rules: &[CompiledRule],
    m: &Msg,
    exists: &BTreeSet<String>,
    trash: Option<&str>,
    create: &mut BTreeSet<String>,
    notes: &mut BTreeSet<String>,
) -> MsgPlan {
    let mut p = MsgPlan {
        uid: m.uid,
        ..Default::default()
    };
    let mut implicit_keep = true;
    let mut explicit_keep = false;
    let mut folders: Vec<String> = Vec::new();
    'rules: for r in rules {
        if !r.matches(m) {
            continue;
        }
        for a in &r.rule.actions {
            match a {
                Action::Fileinto { folder, create: c, copy } => {
                    let folder = folder.trim();
                    if folder.eq_ignore_ascii_case(INBOX) {
                        explicit_keep = true;
                        continue;
                    }
                    if !exists.contains(folder) {
                        if *c {
                            create.insert(folder.to_string());
                        } else {
                            // Sieve would fail and fall back to keep.
                            notes.insert(format!(
                                "Folder \"{folder}\" doesn't exist and \"Create if missing\" is off, so those messages stay in the Inbox."
                            ));
                            explicit_keep = true;
                            continue;
                        }
                    }
                    if !folders.iter().any(|f| f == folder) {
                        folders.push(folder.to_string());
                    }
                    if !copy {
                        implicit_keep = false;
                    }
                }
                Action::Redirect { address, copy } => {
                    if !p.forwards.contains(address) {
                        p.forwards.push(address.clone());
                    }
                    if !copy {
                        implicit_keep = false;
                    }
                }
                Action::Keep => explicit_keep = true,
                Action::Discard => implicit_keep = false,
                Action::Flag { flags } => {
                    for f in flags.list().iter().flat_map(|v| v.split_whitespace()) {
                        if !p.flags.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                            p.flags.push(f.to_string());
                        }
                    }
                }
                Action::Reject { .. } => {
                    notes.insert(
                        "Reject isn't applied to existing mail (it would bounce old messages)."
                            .into(),
                    );
                }
                Action::Vacation { .. } => {
                    notes.insert(
                        "Auto-reply isn't applied to existing mail (it would reply to old senders)."
                            .into(),
                    );
                }
                Action::Stop => break 'rules,
            }
        }
        if r.rule.stop {
            break;
        }
    }
    let in_inbox = implicit_keep || explicit_keep;
    if in_inbox {
        p.copies = folders;
    } else if let Some(last) = folders.pop() {
        p.copies = folders;
        p.move_to = Some(last);
    } else {
        // Discard, or forward without keeping a copy: nothing should stay.
        match trash {
            Some(t) => p.move_to = Some(t.to_string()),
            None => {
                notes.insert(
                    "No Trash folder found, so messages the rule would delete stay in the Inbox."
                        .into(),
                );
            }
        }
    }
    p
}

fn describe(p: &MsgPlan) -> String {
    let mut parts = Vec::new();
    if !p.forwards.is_empty() {
        parts.push(format!("Forward to {}", p.forwards.join(", ")));
    }
    if !p.flags.is_empty() {
        let names: Vec<&str> = p.flags.iter().map(|f| flag_name(f)).collect();
        parts.push(format!("Mark {}", names.join(", ")));
    }
    for c in &p.copies {
        parts.push(format!("Copy to {c}"));
    }
    if let Some(t) = &p.move_to {
        parts.push(format!("Move to {t}"));
    }
    parts.join(" · ")
}

fn flag_name(f: &str) -> &str {
    match f.to_ascii_lowercase().as_str() {
        "\\seen" => "read",
        "\\flagged" => "flagged",
        "\\answered" => "answered",
        "\\deleted" => "deleted",
        "\\draft" => "draft",
        _ => f,
    }
}

// ---------------------------------------------------------------------------
// Messages

struct Msg {
    uid: u32,
    size: u64,
    /// (lower-case name, decoded unfolded value), in order.
    headers: Vec<(String, String)>,
    /// (lower-case name, address) for every address in address headers.
    addresses: Vec<(String, String)>,
    body: String,
    from_display: String,
    subject: String,
    date: String,
}

impl Msg {
    fn parse(parser: &MessageParser, f: &Fetched, with_body: bool) -> Option<Msg> {
        let m = parser.parse(&f.data)?;
        let raw = m.raw_message();
        let mut headers = Vec::new();
        let mut addresses = Vec::new();
        for h in m.headers() {
            let name = h.name.as_str().to_ascii_lowercase();
            let start = h.offset_start as usize;
            let end = (h.offset_end as usize).min(raw.len());
            let mut bytes = raw.get(start..end).unwrap_or_default().to_vec();
            if bytes.last() != Some(&b'\n') {
                bytes.push(b'\n');
            }
            let value = MessageStream::new(&bytes)
                .parse_unstructured()
                .as_text()
                .unwrap_or_default()
                .trim()
                .to_string();
            if let Some(a) = h.value.as_address() {
                for addr in a.iter() {
                    if let Some(x) = &addr.address {
                        addresses.push((name.clone(), x.to_string()));
                    }
                }
            }
            headers.push((name, value));
        }
        let body = if with_body {
            (0..)
                .map_while(|i| m.body_text(i))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };
        let from_display = m
            .from()
            .and_then(|a| a.first())
            .map(|a| {
                a.name
                    .as_deref()
                    .filter(|n| !n.trim().is_empty())
                    .or(a.address.as_deref())
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default();
        Some(Msg {
            uid: f.uid,
            size: f.size,
            subject: m.subject().unwrap_or("(no subject)").to_string(),
            date: m
                .date()
                .map(|d| d.to_rfc3339().chars().take(10).collect())
                .unwrap_or_default(),
            headers,
            addresses,
            body,
            from_display,
        })
    }

    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Addresses in an address header. Headers the parser didn't treat as
    /// addresses (e.g. Delivered-To) fall back to the bare `<addr>` or text.
    fn address_values(&self, name: &str) -> Vec<String> {
        let parsed: Vec<String> = self
            .addresses
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, a)| a.clone())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
        self.header_values(name)
            .map(|v| {
                let v = v.trim();
                match (v.rfind('<'), v.rfind('>')) {
                    (Some(a), Some(b)) if a < b => v[a + 1..b].to_string(),
                    _ => v.to_string(),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Conditions

struct CompiledRule<'a> {
    rule: &'a Rule,
    conds: Vec<CompiledCond>,
    needs_body: bool,
}

impl<'a> CompiledRule<'a> {
    fn new(rule: &'a Rule) -> Result<Self> {
        let conds: Vec<CompiledCond> = rule
            .conditions
            .iter()
            .map(CompiledCond::new)
            .collect::<Result<_>>()
            .with_context(|| format!("rule {:?}", rule.name))?;
        let needs_body = conds.iter().any(|c| matches!(c.kind, FieldKind::Body));
        Ok(CompiledRule {
            rule,
            conds,
            needs_body,
        })
    }

    fn matches(&self, m: &Msg) -> bool {
        if self.conds.is_empty() {
            return true;
        }
        match self.rule.match_kind {
            MatchKind::All => self.conds.iter().all(|c| c.test(m)),
            MatchKind::Any => self.conds.iter().any(|c| c.test(m)),
        }
    }
}

struct CompiledCond {
    kind: FieldKind,
    part: Option<&'static str>,
    op: Op,
    not: bool,
    case_sensitive: bool,
    values: Vec<String>,
    regexes: Vec<regex::Regex>,
}

impl CompiledCond {
    fn new(c: &Condition) -> Result<Self> {
        let (kind, part) = classify(&c.field)?;
        let values: Vec<String> = c.value.list().iter().map(|s| s.to_string()).collect();
        let regexes = if c.op == Op::Regex {
            values
                .iter()
                .map(|v| {
                    regex::RegexBuilder::new(v)
                        .case_insensitive(!c.case_sensitive)
                        .build()
                        .with_context(|| format!("invalid regex {v:?}"))
                })
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };
        Ok(CompiledCond {
            kind,
            part,
            op: c.op,
            not: c.not,
            case_sensitive: c.case_sensitive,
            values,
            regexes,
        })
    }

    fn test(&self, m: &Msg) -> bool {
        self.not != self.test_inner(m)
    }

    fn test_inner(&self, m: &Msg) -> bool {
        match self.op {
            Op::Exists => {
                // Sieve `exists`: true only if every named header is present.
                let names: Vec<&str> = match &self.kind {
                    FieldKind::Address(h) => h.to_vec(),
                    FieldKind::Header(h) => vec![h.as_str()],
                    _ => return false,
                };
                names.iter().all(|n| m.header_values(n).next().is_some())
            }
            Op::Over | Op::Under => {
                let Some(limit) = self.values.first().and_then(|v| parse_size(v)) else {
                    return false;
                };
                if self.op == Op::Over {
                    m.size > limit
                } else {
                    m.size < limit
                }
            }
            Op::Is | Op::Contains | Op::Matches | Op::Regex => {
                let hay: Vec<String> = match &self.kind {
                    FieldKind::Address(hs) => hs
                        .iter()
                        .flat_map(|h| m.address_values(h))
                        .map(|a| self.address_part(&a))
                        .collect(),
                    FieldKind::Envelope(e) => {
                        let src: &[&str] = if *e == "from" {
                            &["return-path"]
                        } else {
                            &["delivered-to", "x-original-to", "envelope-to"]
                        };
                        src.iter()
                            .flat_map(|h| m.address_values(h))
                            .map(|a| self.address_part(&a))
                            .collect()
                    }
                    FieldKind::Header(h) => m.header_values(h).map(str::to_string).collect(),
                    FieldKind::Body => vec![m.body.clone()],
                    FieldKind::Size => return false,
                };
                hay.iter().any(|h| self.match_any(h))
            }
        }
    }

    fn address_part(&self, addr: &str) -> String {
        let (local, domain) = addr.rsplit_once('@').unwrap_or((addr, ""));
        match self.part {
            Some(":domain") => domain.to_string(),
            Some(":localpart") => local.to_string(),
            _ => addr.to_string(),
        }
    }

    fn match_any(&self, hay: &str) -> bool {
        if self.op == Op::Regex {
            return self.regexes.iter().any(|r| r.is_match(hay));
        }
        // i;ascii-casemap folds ASCII only; i;octet compares bytes.
        let fold = |s: &str| {
            if self.case_sensitive {
                s.to_string()
            } else {
                s.to_ascii_lowercase()
            }
        };
        let h = fold(hay);
        self.values.iter().any(|v| {
            let v = fold(v);
            match self.op {
                Op::Is => h == v,
                Op::Contains => h.contains(&v),
                _ => glob(&h, &v),
            }
        })
    }
}

/// `500K`, `5M`, `1G`, or a byte count.
fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim().to_ascii_uppercase();
    let (num, mult) = match v.chars().last()? {
        'K' => (&v[..v.len() - 1], 1024),
        'M' => (&v[..v.len() - 1], 1024 * 1024),
        'G' => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        _ => (v.as_str(), 1),
    };
    num.parse::<u64>().ok().map(|n| n * mult)
}

/// Sieve `:matches`: `*` any run, `?` one character, `\` escapes.
fn glob(hay: &str, pat: &str) -> bool {
    let h: Vec<char> = hay.chars().collect();
    let mut p: Vec<(char, bool)> = Vec::new(); // (char, is_literal)
    let mut it = pat.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            if let Some(n) = it.next() {
                p.push((n, true));
            }
        } else {
            p.push((c, false));
        }
    }
    let (mut hi, mut pi) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while hi < h.len() {
        if pi < p.len() && !p[pi].1 && p[pi].0 == '*' {
            star = Some(pi);
            mark = hi;
            pi += 1;
        } else if pi < p.len() && ((!p[pi].1 && p[pi].0 == '?') || p[pi].0 == h[hi]) {
            hi += 1;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            hi = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && !p[pi].1 && p[pi].0 == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn rules(toml: &str) -> Vec<Rule> {
        toml::from_str::<RuleSet>(toml).unwrap().rules
    }

    fn msg(raw: &str, size: u64) -> Msg {
        let f = Fetched {
            uid: 7,
            size,
            data: raw.replace('\n', "\r\n").into_bytes(),
        };
        Msg::parse(&MessageParser::default(), &f, true).unwrap()
    }

    const ALMA: &str = "From: \"Alma Bot\" <announce@lists.almalinux.org>\n\
To: Jeff <me@example.com>, users@lists.almalinux.org\n\
Subject: =?utf-8?q?Caf=C3=A9_release?=\n\
List-Id: AlmaLinux users <users.lists.almalinux.org>\n\
Date: Sat, 10 Oct 2026 12:00:00 +0000\n\
\n\
Hello body text\n";

    fn plan(rs: &[Rule], m: &Msg, exists: &[&str]) -> (MsgPlan, BTreeSet<String>) {
        let c: Vec<CompiledRule> = rs.iter().map(|r| CompiledRule::new(r).unwrap()).collect();
        let exists = exists.iter().map(|s| s.to_string()).collect();
        let mut create = BTreeSet::new();
        let mut notes = BTreeSet::new();
        let p = plan_message(&c, m, &exists, Some("Trash"), &mut create, &mut notes);
        (p, notes)
    }

    #[test]
    fn move_on_address_contains() {
        let rs = rules(
            r#"[[rule]]
name = "Alma"
if = [{ field = "to", op = "contains", value = "users@lists.almalinux.org" }]
then = [{ action = "fileinto", folder = "Alma Linux" }]"#,
        );
        let m = msg(ALMA, 100);
        let (p, _) = plan(&rs, &m, &["Alma Linux"]);
        assert_eq!(p.move_to.as_deref(), Some("Alma Linux"));
        assert!(p.copies.is_empty());
    }

    #[test]
    fn conditions() {
        let m = msg(ALMA, 2_000_000);
        let t = |field: &str, op: &str, v: &str| {
            let rs = rules(&format!(
                "[[rule]]\nname = \"t\"\nif = [{{ field = \"{field}\", op = \"{op}\", value = \"{v}\" }}]\nthen = [{{ action = \"keep\" }}]"
            ));
            CompiledRule::new(&rs[0]).unwrap().matches(&m)
        };
        assert!(t("from.domain", "is", "lists.almalinux.org"));
        assert!(t("from.localpart", "is", "ANNOUNCE"));
        assert!(!t("from.domain", "is", "almalinux.org"));
        assert!(t("subject", "contains", "café"), "RFC 2047 subject is decoded");
        assert!(t("subject", "matches", "*release"));
        assert!(t("list-id", "contains", "users.lists.almalinux.org"));
        assert!(t("body", "contains", "body text"));
        assert!(t("subject", "regex", "^caf.+ rel"));
        assert!(t("size", "over", "1M"));
        assert!(!t("size", "under", "1M"));
        assert!(t("list-id", "exists", ""));
        assert!(!t("x-nope", "exists", ""));
    }

    #[test]
    fn copy_flags_and_discard() {
        let m = msg(ALMA, 1);
        let rs = rules(
            r#"[[rule]]
name = "Copy and read"
then = [{ action = "fileinto", folder = "Archive", copy = true }, { action = "flag", flags = "\\Seen" }]"#,
        );
        let (p, _) = plan(&rs, &m, &["Archive"]);
        assert_eq!(p.copies, vec!["Archive"]);
        assert_eq!(p.move_to, None);
        assert_eq!(p.flags, vec!["\\Seen"]);

        let rs = rules("[[rule]]\nname = \"d\"\nthen = [{ action = \"discard\" }]");
        let (p, _) = plan(&rs, &m, &[]);
        assert_eq!(p.move_to.as_deref(), Some("Trash"));
    }

    #[test]
    fn missing_folder_and_stop() {
        let m = msg(ALMA, 1);
        let rs = rules(
            r#"[[rule]]
name = "a"
then = [{ action = "fileinto", folder = "Nope" }]
stop = true

[[rule]]
name = "b"
then = [{ action = "fileinto", folder = "Other" }]"#,
        );
        let (p, notes) = plan(&rs, &m, &["Other"]);
        assert!(p.is_noop(), "missing folder keeps it in the Inbox; stop skips rule b");
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn vacation_is_skipped() {
        let m = msg(ALMA, 1);
        let rs = rules("[[rule]]\nname = \"v\"\nthen = [{ action = \"vacation\", reason = \"away\" }]");
        let (p, notes) = plan(&rs, &m, &[]);
        assert!(p.is_noop());
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn globbing() {
        assert!(glob("hello world", "hello*"));
        assert!(glob("hello world", "*o w*"));
        assert!(glob("abc", "a?c"));
        assert!(!glob("abc", "a?d"));
        assert!(glob("a*c", "a\\*c"));
        assert!(!glob("abc", "a\\*c"));
        assert!(glob("", "*"));
    }
}
