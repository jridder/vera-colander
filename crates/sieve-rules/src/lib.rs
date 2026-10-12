//! Rule model (stored as TOML) and the compiler that turns it into Sieve (RFC 5228).

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Sieve extensions a script needs, for its single merged `require`.
pub type Requires = BTreeSet<String>;

fn yes() -> bool {
    true
}
fn is_false(b: &bool) -> bool {
    !*b
}
fn is_true(b: &bool) -> bool {
    *b
}

/// The one script Vera Colander owns on the server and keeps active.
pub const SCRIPT_NAME: &str = "vera-colander";

/// Everything that goes into the script: groups of rules, top to bottom.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(default, rename = "group", skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<Group>,
    /// Ungrouped rules, from files and scripts written before groups existed.
    /// They compile before the groups; `grouped` moves them into a group.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

impl Group {
    pub fn new(name: impl Into<String>) -> Self {
        Group {
            name: name.into(),
            enabled: true,
            rules: Vec::new(),
        }
    }
}

impl RuleSet {
    /// Move ungrouped rules into a group called `name`, placed first (they
    /// ran first before), so everything lives in groups.
    pub fn grouped(mut self, name: &str) -> Self {
        if !self.rules.is_empty() {
            let mut g = Group::new(name);
            g.rules = std::mem::take(&mut self.rules);
            self.groups.insert(0, g);
        }
        self
    }

    pub fn group_index(&self, name: &str) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.name.eq_ignore_ascii_case(name))
    }

    /// Every rule with its group index, in script order.
    pub fn all_rules(&self) -> impl Iterator<Item = (usize, &Rule)> {
        self.groups
            .iter()
            .enumerate()
            .flat_map(|(gi, g)| g.rules.iter().map(move |r| (gi, r)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// A raw Sieve block, inserted verbatim (its `require`s are hoisted).
    /// When set, the condition/action fields are ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, rename = "match", skip_serializing_if = "MatchKind::is_all")]
    pub match_kind: MatchKind,
    #[serde(default, rename = "if", skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, rename = "then", skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stop: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    #[default]
    All,
    Any,
}
impl MatchKind {
    fn is_all(&self) -> bool {
        *self == MatchKind::All
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    #[serde(default, skip_serializing_if = "Values::is_empty")]
    pub value: Values,
    #[serde(default, skip_serializing_if = "is_false")]
    pub not: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Is,
    Contains,
    Matches,
    Regex,
    Exists,
    Over,
    Under,
}

impl Op {
    fn parse(s: &str) -> Result<Op> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "is" | "==" | "=" => Op::Is,
            "contains" | "has" => Op::Contains,
            "matches" | "like" => Op::Matches,
            "regex" | "~" => Op::Regex,
            "exists" => Op::Exists,
            "over" | ">" => Op::Over,
            "under" | "<" => Op::Under,
            _ => {
                bail!("unknown operator {s:?} (is, contains, matches, regex, exists, over, under)")
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Values {
    One(String),
    Many(Vec<String>),
}
impl Default for Values {
    fn default() -> Self {
        Values::Many(Vec::new())
    }
}
impl Values {
    pub fn list(&self) -> Vec<&str> {
        match self {
            Values::One(s) => vec![s.as_str()],
            Values::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
    fn is_empty(&self) -> bool {
        self.list().is_empty()
    }
    fn from_vec(mut v: Vec<String>) -> Self {
        if v.len() == 1 {
            Values::One(v.remove(0))
        } else {
            Values::Many(v)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum Action {
    Fileinto {
        folder: String,
        #[serde(default, skip_serializing_if = "is_false")]
        create: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        copy: bool,
    },
    Redirect {
        address: String,
        #[serde(default, skip_serializing_if = "is_false")]
        copy: bool,
    },
    Keep,
    Discard,
    Reject {
        reason: String,
    },
    Flag {
        flags: Values,
    },
    Vacation {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        days: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(default, skip_serializing_if = "Values::is_empty")]
        addresses: Values,
    },
    Stop,
}

// ---------------------------------------------------------------------------
// Loading / saving

/// Default group for rules that don't name one.
pub const DEFAULT_GROUP: &str = "Rules";

pub fn load(path: &std::path::Path) -> Result<RuleSet> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let set: RuleSet =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(set.grouped(DEFAULT_GROUP))
}

pub fn load_or_empty(path: &std::path::Path) -> Result<RuleSet> {
    if path.exists() {
        load(path)
    } else {
        Ok(RuleSet::default())
    }
}

pub fn save(path: &std::path::Path, set: &RuleSet) -> Result<()> {
    compile(set).context("refusing to save an invalid rule set")?;
    let text = toml::to_string(set)?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

// ---------------------------------------------------------------------------
// Compiler

pub const HEADER: &str =
    "# Generated by Vera Colander (sievectl). Manual edits will be overwritten.\n";

/// Compile all enabled groups and rules, top to bottom, into one script with
/// a single merged `require` at the top and the rule set embedded at the end.
pub fn compile(set: &RuleSet) -> Result<String> {
    fn emit(rules: &[Rule], live: bool, req: &mut Requires, body: &mut String) -> Result<()> {
        for (i, r) in rules.iter().enumerate() {
            let mut local_req = Requires::new();
            let block = compile_rule(r, &mut local_req)
                .with_context(|| format!("rule #{} {:?}", i + 1, r.name))?;
            body.push('\n');
            if live && r.enabled {
                req.extend(local_req);
                body.push_str(&block);
            } else {
                body.push_str(&format!("# [disabled] {}\n", one_line(&r.name)));
            }
        }
        Ok(())
    }
    let mut req = Requires::new();
    let mut body = String::new();
    emit(&set.rules, true, &mut req, &mut body)?;
    for g in &set.groups {
        let mark = if g.enabled { "" } else { " [disabled]" };
        body.push_str(&format!("\n# ==== group: {}{mark} ====\n", one_line(&g.name)));
        emit(&g.rules, g.enabled, &mut req, &mut body)
            .with_context(|| format!("group {:?}", g.name))?;
    }
    let mut out = String::from(HEADER);
    if !req.is_empty() {
        let list: Vec<String> = req.iter().map(|r| quote(r)).collect();
        out.push_str(&format!("require [{}];\n", list.join(", ")));
    }
    out.push_str(&body);
    out.push_str(&embed(set)?);
    Ok(out)
}

const EMBED_BEGIN: &str = "#@sievectl-rules-begin";
const EMBED_END: &str = "#@sievectl-rules-end";

/// The rule set as TOML inside Sieve comments, so any machine can reopen
/// the script on the server as editable rules.
fn embed(set: &RuleSet) -> Result<String> {
    let toml = toml::to_string(set)?;
    let mut s = format!("\n{EMBED_BEGIN}\n");
    for line in toml.lines() {
        s.push_str("#@ ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str(EMBED_END);
    s.push('\n');
    Ok(s)
}

/// The script with the generated header and embedded rules block removed.
pub fn without_embedded(script: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for l in script.lines() {
        if l == EMBED_BEGIN {
            inside = true;
        } else if l == EMBED_END {
            inside = false;
        } else if !inside && format!("{l}\n") != HEADER {
            out.push_str(l);
            out.push('\n');
        }
    }
    out.trim_end().to_string() + "\n"
}

/// Recover the rule set embedded by `compile`, if the script has one.
pub fn extract(script: &str) -> Option<Result<RuleSet>> {
    let mut lines = script.lines().map(|l| l.trim_end_matches('\r'));
    lines.by_ref().find(|l| *l == EMBED_BEGIN)?;
    let mut toml = String::new();
    for l in lines {
        if l == EMBED_END {
            return Some(toml::from_str(&toml).context("embedded rules are corrupt"));
        }
        toml.push_str(
            l.strip_prefix("#@ ")
                .or_else(|| l.strip_prefix("#@"))
                .unwrap_or(l),
        );
        toml.push('\n');
    }
    Some(Err(anyhow!("embedded rules block is not terminated")))
}

pub fn compile_rule(r: &Rule, req: &mut Requires) -> Result<String> {
    if let Some(raw) = &r.raw {
        let (text, exts) = hoist_requires(raw);
        req.extend(exts);
        let text = text.trim_matches('\n').trim_end();
        return Ok(format!("# rule: {} (raw Sieve)\n{text}\n", one_line(&r.name)));
    }
    if r.actions.is_empty() && !r.stop {
        bail!("rule has no actions");
    }
    let mut actions = Vec::new();
    for a in &r.actions {
        actions.push(compile_action(a, req)?);
    }
    if r.stop && !matches!(r.actions.last(), Some(Action::Stop)) {
        actions.push("stop;".into());
    }
    let mut out = format!("# rule: {}\n", one_line(&r.name));
    if r.conditions.is_empty() {
        for a in actions {
            out.push_str(&a);
            out.push('\n');
        }
        return Ok(out);
    }
    let tests: Vec<String> = r
        .conditions
        .iter()
        .enumerate()
        .map(|(i, c)| compile_condition(c, req).with_context(|| format!("condition #{}", i + 1)))
        .collect::<Result<_>>()?;
    let test = if tests.len() == 1 {
        tests[0].clone()
    } else {
        let kw = if r.match_kind == MatchKind::Any {
            "anyof"
        } else {
            "allof"
        };
        format!("{kw} (\n    {}\n)", tests.join(",\n    "))
    };
    out.push_str(&format!("if {test} {{\n"));
    for a in actions {
        out.push_str(&format!("    {a}\n"));
    }
    out.push_str("}\n");
    Ok(out)
}

pub enum FieldKind {
    Address(Vec<&'static str>),
    Envelope(&'static str),
    Header(String),
    Body,
    Size,
}

const ADDRESS_FIELDS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "sender",
    "reply-to",
    "resent-from",
    "resent-to",
];

pub fn classify(field: &str) -> Result<(FieldKind, Option<&'static str>)> {
    let f = field.trim().to_ascii_lowercase();
    let (base, part) = match f.rsplit_once('.') {
        Some((b, "domain")) => (b.to_string(), Some(":domain")),
        Some((b, "localpart")) | Some((b, "local")) => (b.to_string(), Some(":localpart")),
        Some((b, "all")) => (b.to_string(), Some(":all")),
        _ => (f.clone(), None),
    };
    let kind = match base.as_str() {
        "to-or-cc" | "recipient" => FieldKind::Address(vec!["to", "cc"]),
        "envelope-from" => FieldKind::Envelope("from"),
        "envelope-to" => FieldKind::Envelope("to"),
        "body" => FieldKind::Body,
        "size" => FieldKind::Size,
        b if ADDRESS_FIELDS.contains(&b) => {
            FieldKind::Address(vec![ADDRESS_FIELDS.iter().find(|x| **x == b).unwrap()])
        }
        b => {
            let h = b.strip_prefix("header:").unwrap_or(b);
            if h.is_empty() || !h.bytes().all(|c| c.is_ascii_graphic() && c != b':') {
                bail!("invalid field/header name {field:?}");
            }
            FieldKind::Header(h.to_string())
        }
    };
    if part.is_some() && !matches!(kind, FieldKind::Address(_) | FieldKind::Envelope(_)) {
        bail!("{field:?}: .domain/.localpart only apply to address fields");
    }
    Ok((kind, part))
}

fn compile_condition(c: &Condition, req: &mut Requires) -> Result<String> {
    let (kind, part) = classify(&c.field)?;
    let vals = c.value.list();
    let cmp = if c.case_sensitive {
        " :comparator \"i;octet\""
    } else {
        ""
    };
    let test = match c.op {
        Op::Exists => {
            let names: Vec<String> = match kind {
                FieldKind::Address(h) => h.into_iter().map(String::from).collect(),
                FieldKind::Header(h) => vec![h],
                _ => bail!("'exists' only works on header fields"),
            };
            format!(
                "exists {}",
                strlist(&names.iter().map(String::as_str).collect::<Vec<_>>())
            )
        }
        Op::Over | Op::Under => {
            if !matches!(kind, FieldKind::Size) {
                bail!("over/under only apply to field \"size\"");
            }
            let [v] = vals.as_slice() else {
                bail!("size needs exactly one value, e.g. \"5M\"")
            };
            let v = v.trim().to_ascii_uppercase();
            let digits = v.trim_end_matches(['K', 'M', 'G']);
            if digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit())
                || v.len() - digits.len() > 1
            {
                bail!("invalid size {v:?} (use e.g. 500K, 5M, 1G)");
            }
            format!(
                "size :{} {v}",
                if c.op == Op::Over { "over" } else { "under" }
            )
        }
        Op::Is | Op::Contains | Op::Matches | Op::Regex => {
            if matches!(kind, FieldKind::Size) {
                bail!("field \"size\" needs op over or under");
            }
            if vals.is_empty() {
                bail!("missing value");
            }
            let mt = match c.op {
                Op::Is => ":is",
                Op::Contains => ":contains",
                Op::Matches => ":matches",
                _ => {
                    req.insert("regex".into());
                    ":regex"
                }
            };
            let part = part.map(|p| format!(" {p}")).unwrap_or_default();
            let v = strlist(&vals);
            match kind {
                FieldKind::Address(h) => format!("address{part} {mt}{cmp} {} {v}", strlist(&h)),
                FieldKind::Envelope(e) => {
                    req.insert("envelope".into());
                    format!("envelope{part} {mt}{cmp} {} {v}", quote(e))
                }
                FieldKind::Header(h) => format!("header {mt}{cmp} {} {v}", quote(&h)),
                FieldKind::Body => {
                    req.insert("body".into());
                    format!("body :text {mt}{cmp} {v}")
                }
                FieldKind::Size => unreachable!(),
            }
        }
    };
    Ok(if c.not { format!("not {test}") } else { test })
}

fn compile_action(a: &Action, req: &mut Requires) -> Result<String> {
    Ok(match a {
        Action::Fileinto {
            folder,
            create,
            copy,
        } => {
            if folder.trim().is_empty() {
                bail!("fileinto needs a folder");
            }
            req.insert("fileinto".into());
            let mut s = String::from("fileinto");
            if *create {
                req.insert("mailbox".into());
                s.push_str(" :create");
            }
            if *copy {
                req.insert("copy".into());
                s.push_str(" :copy");
            }
            format!("{s} {};", quote(folder))
        }
        Action::Redirect { address, copy } => {
            if !address.contains('@') {
                bail!("redirect needs an email address, got {address:?}");
            }
            if *copy {
                req.insert("copy".into());
                format!("redirect :copy {};", quote(address))
            } else {
                format!("redirect {};", quote(address))
            }
        }
        Action::Keep => "keep;".into(),
        Action::Discard => "discard;".into(),
        Action::Stop => "stop;".into(),
        Action::Reject { reason } => {
            req.insert("reject".into());
            format!("reject {};", quote(reason))
        }
        Action::Flag { flags } => {
            if flags.is_empty() {
                bail!("flag needs at least one flag");
            }
            req.insert("imap4flags".into());
            format!("addflag {};", strlist(&flags.list()))
        }
        Action::Vacation {
            reason,
            subject,
            days,
            from,
            addresses,
        } => {
            req.insert("vacation".into());
            let mut s = String::from("vacation");
            if let Some(d) = days {
                s.push_str(&format!(" :days {d}"));
            }
            if let Some(sub) = subject {
                s.push_str(&format!(" :subject {}", quote(sub)));
            }
            if let Some(f) = from {
                s.push_str(&format!(" :from {}", quote(f)));
            }
            if !addresses.is_empty() {
                s.push_str(&format!(" :addresses {}", strlist(&addresses.list())));
            }
            format!("{s} {};", quote(reason))
        }
    })
}

/// Turn a script from the server into groups for the one-script model.
/// Scripts made by this app keep their groups and rules; anything else
/// becomes a group holding one raw Sieve block. Only the active script was
/// running, so `live == false` brings the groups in disabled.
pub fn import_script(name: &str, content: &str, live: bool) -> Vec<Group> {
    let content = content.replace("\r\n", "\n");
    let mut groups = match extract(&content) {
        Some(Ok(set)) => set.grouped(name).groups,
        _ => vec![Group {
            name: name.to_string(),
            enabled: true,
            rules: vec![Rule {
                name: format!("Imported “{name}”"),
                enabled: true,
                raw: Some(without_embedded(&content)),
                match_kind: MatchKind::All,
                conditions: Vec::new(),
                actions: Vec::new(),
                stop: false,
            }],
        }],
    };
    for g in &mut groups {
        g.enabled &= live;
    }
    groups
}

/// Split `require` commands out of a hand-written Sieve block: returns the
/// block without them, and the extensions they named (lower-cased). Comments,
/// strings and `text:` blocks are skipped, so only real commands are touched.
pub fn hoist_requires(src: &str) -> (String, Vec<String>) {
    let b = src.as_bytes();
    let mut exts = Vec::new();
    let mut cut: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    let mut at_cmd = true;
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_whitespace() => i += 1,
            b'#' => i = skip_line(b, i),
            b'/' if b.get(i + 1) == Some(&b'*') => i = skip_block_comment(b, i),
            b'"' => {
                i = read_string(b, i).0;
                at_cmd = false;
            }
            b';' | b'{' | b'}' => {
                at_cmd = true;
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                    i += 1;
                }
                let word = &src[start..i];
                if word.eq_ignore_ascii_case("text") && b.get(i) == Some(&b':') {
                    i = skip_text_block(b, i + 1);
                    at_cmd = false;
                } else if at_cmd && word.eq_ignore_ascii_case("require") {
                    if let Some((end, names)) = parse_require_args(b, i) {
                        // Take the rest of the line too, if it's only whitespace.
                        let mut e = end;
                        while e < b.len() && (b[e] == b' ' || b[e] == b'\t') {
                            e += 1;
                        }
                        if b.get(e) == Some(&b'\r') {
                            e += 1;
                        }
                        if b.get(e) == Some(&b'\n') {
                            e += 1;
                        } else {
                            e = end;
                        }
                        cut.push((start, e));
                        exts.extend(names.into_iter().map(|n| n.to_ascii_lowercase()));
                        i = end;
                        at_cmd = true;
                        continue;
                    }
                    at_cmd = false;
                } else {
                    at_cmd = false;
                }
            }
            _ => {
                at_cmd = false;
                i += 1;
            }
        }
    }
    let mut out = String::with_capacity(src.len());
    let mut last = 0;
    for (a, z) in cut {
        out.push_str(&src[last..a]);
        last = z;
    }
    out.push_str(&src[last..]);
    (out, exts)
}

fn skip_ws_comments(b: &[u8], mut i: usize) -> usize {
    loop {
        match b.get(i) {
            Some(c) if c.is_ascii_whitespace() => i += 1,
            Some(b'#') => i = skip_line(b, i),
            Some(b'/') if b.get(i + 1) == Some(&b'*') => i = skip_block_comment(b, i),
            _ => return i,
        }
    }
}

fn skip_line(b: &[u8], i: usize) -> usize {
    b[i..].iter().position(|&c| c == b'\n').map_or(b.len(), |p| i + p + 1)
}

fn skip_block_comment(b: &[u8], i: usize) -> usize {
    b[i + 2..]
        .windows(2)
        .position(|w| w == b"*/")
        .map_or(b.len(), |p| i + 2 + p + 2)
}

/// `"…"` starting at `i`; returns (index after the closing quote, contents).
fn read_string(b: &[u8], mut i: usize) -> (usize, String) {
    let mut v = Vec::new();
    i += 1;
    while i < b.len() {
        match b[i] {
            b'"' => return (i + 1, String::from_utf8_lossy(&v).into_owned()),
            b'\\' if i + 1 < b.len() => {
                v.push(b[i + 1]);
                i += 2;
            }
            c => {
                v.push(c);
                i += 1;
            }
        }
    }
    (b.len(), String::from_utf8_lossy(&v).into_owned())
}

/// After `text:`: skip to the line holding only ".".
fn skip_text_block(b: &[u8], i: usize) -> usize {
    let mut i = skip_line(b, i);
    while i < b.len() {
        let next = skip_line(b, i);
        let line = &b[i..next];
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line == b"." {
            return next;
        }
        i = next;
    }
    b.len()
}

/// The arguments of `require` (a string or string list) and its `;`.
fn parse_require_args(b: &[u8], i: usize) -> Option<(usize, Vec<String>)> {
    let mut i = skip_ws_comments(b, i);
    let mut names = Vec::new();
    match b.get(i)? {
        b'"' => {
            let (j, s) = read_string(b, i);
            names.push(s);
            i = j;
        }
        b'[' => {
            i += 1;
            loop {
                i = skip_ws_comments(b, i);
                match b.get(i)? {
                    b'"' => {
                        let (j, s) = read_string(b, i);
                        names.push(s);
                        i = j;
                    }
                    b',' => i += 1,
                    b']' => {
                        i += 1;
                        break;
                    }
                    _ => return None,
                }
            }
        }
        _ => return None,
    }
    i = skip_ws_comments(b, i);
    (b.get(i) == Some(&b';')).then_some((i + 1, names))
}

/// Extensions named in the script's `require` line.
pub fn required(script: &str) -> Vec<String> {
    script
        .lines()
        .find(|l| l.starts_with("require"))
        .map(|l| l.split('"').skip(1).step_by(2).map(String::from).collect())
        .unwrap_or_default()
}

pub fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn strlist(v: &[&str]) -> String {
    if v.len() == 1 {
        quote(v[0])
    } else {
        format!(
            "[{}]",
            v.iter().map(|s| quote(s)).collect::<Vec<_>>().join(", ")
        )
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\r', '\n'], " ")
}

// ---------------------------------------------------------------------------
// One-line syntax used by `sievectl rule add --if ... --then ...`

fn take_word(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    match s.find(char::is_whitespace) {
        Some(i) => (&s[..i], s[i..].trim_start()),
        None => (s, ""),
    }
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// `FIELD [not] OP [VALUE[|VALUE...]]`, e.g. `from.domain is github.com`,
/// `subject contains invoice|receipt`, `list-id exists`, `size over 10M`.
pub fn parse_condition(s: &str) -> Result<Condition> {
    let (field, rest) = take_word(s);
    if field.is_empty() {
        bail!("empty condition");
    }
    let (mut op, mut rest) = take_word(rest);
    let mut not = false;
    if op.eq_ignore_ascii_case("not") || op == "!" {
        not = true;
        (op, rest) = take_word(rest);
    }
    let op = Op::parse(op).with_context(|| format!("in condition {s:?}"))?;
    let vals: Vec<String> = if rest.is_empty() {
        vec![]
    } else {
        rest.split('|')
            .map(unquote)
            .filter(|v| !v.is_empty())
            .collect()
    };
    let c = Condition {
        field: field.to_string(),
        op,
        value: Values::from_vec(vals),
        not,
        case_sensitive: false,
    };
    compile_condition(&c, &mut BTreeSet::new()).with_context(|| format!("in condition {s:?}"))?;
    Ok(c)
}

/// `fileinto FOLDER`, `copy FOLDER`, `redirect ADDR`, `forward ADDR`, `keep`,
/// `discard`, `reject REASON`, `flag FLAG...`, `read`, `vacation TEXT`, `stop`.
pub fn parse_action(s: &str, create: bool) -> Result<Action> {
    let (verb, rest) = take_word(s);
    let arg = unquote(rest);
    let need = |what: &str| -> Result<String> {
        if arg.is_empty() {
            Err(anyhow!("{verb} needs {what}"))
        } else {
            Ok(arg.clone())
        }
    };
    Ok(match verb.to_ascii_lowercase().as_str() {
        "fileinto" | "move" | "folder" => Action::Fileinto { folder: need("a folder")?, create, copy: false },
        "copy" | "copyto" => Action::Fileinto { folder: need("a folder")?, create, copy: true },
        "redirect" => Action::Redirect { address: need("an address")?, copy: false },
        "forward" => Action::Redirect { address: need("an address")?, copy: true },
        "keep" => Action::Keep,
        "discard" | "delete" => Action::Discard,
        "stop" => Action::Stop,
        "reject" => Action::Reject { reason: need("a reason")? },
        "flag" => Action::Flag {
            flags: Values::from_vec(rest.split_whitespace().map(unquote).collect()),
        },
        "read" | "seen" => Action::Flag { flags: Values::One("\\Seen".into()) },
        "vacation" => Action::Vacation {
            reason: need("a message")?,
            subject: None,
            days: None,
            from: None,
            addresses: Values::default(),
        },
        _ => bail!("unknown action {verb:?} (fileinto, copy, redirect, forward, keep, discard, reject, flag, read, vacation, stop)"),
    })
}

pub const EXAMPLE: &str = r#"# sievectl rules file
#   sievectl compile rules.toml            -> print the generated Sieve script
#   sievectl deploy rules.toml --activate  -> validate, upload and activate
#
# Rules live in groups. Groups and rules run top to bottom; a disabled group
# (enabled = false) is left out of the script along with all its rules.
#
# field:   from, to, cc, bcc, sender, reply-to, to-or-cc, subject, body, size,
#          envelope-from, envelope-to, or any header name (e.g. "list-id").
#          Address fields accept .domain / .localpart (e.g. "from.domain").
# op:      is, contains, matches (* and ? wildcards), regex, exists, over, under
# value:   a string or a list of strings (any of them matches)
# options: not = true, case_sensitive = true
# match:   "all" (default) or "any" of the conditions
# actions: fileinto (folder, create, copy), redirect (address, copy), keep,
#          discard, reject (reason), flag (flags), vacation (reason, subject,
#          days, from, addresses), stop
# raw:     a rule with raw = """...""" is inserted as hand-written Sieve; its
#          require lines are merged into the script's single require.

[[group]]
name = "Lists"

[[group.rule]]
name = "Debian"
if = [{ field = "list-id", op = "contains", value = "lists.debian.org" }]
then = [{ action = "fileinto", folder = "Lists/Debian", create = true }]
stop = true

[[group]]
name = "Work"

[[group.rule]]
name = "GitHub"
match = "any"
if = [
  { field = "from", op = "is", value = "notifications@github.com" },
  { field = "from.domain", op = "is", value = ["github.com", "githubusercontent.com"] },
]
then = [{ action = "fileinto", folder = "GitHub" }]
stop = true

[[group.rule]]
name = "Receipts"
if = [{ field = "subject", op = "contains", value = ["receipt", "invoice", "order confirmation"] }]
then = [
  { action = "fileinto", folder = "Receipts" },
  { action = "flag", flags = "\\Seen" },
]
stop = true

[[group]]
name = "Housekeeping"

[[group.rule]]
name = "Large mail"
if = [{ field = "size", op = "over", value = "20M" }]
then = [{ action = "flag", flags = "\\Flagged" }]

[[group.rule]]
name = "Out of office"
enabled = false
then = [{ action = "vacation", days = 7, subject = "Away", reason = "I'm away until Monday and will reply when I'm back." }]
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_compiles() {
        let set: RuleSet = toml::from_str(EXAMPLE).unwrap();
        let s = compile(&set).unwrap();
        assert!(
            s.contains(r#"require ["fileinto", "imap4flags", "mailbox"];"#),
            "{s}"
        );
        assert!(s.contains(r#"address :domain :is "from" ["github.com", "githubusercontent.com"]"#));
        assert!(s.contains(r#"addflag "\\Seen";"#));
        assert!(s.contains("size :over 20M"));
        assert!(s.contains("# [disabled] Out of office"));
        assert!(
            !required(&s).contains(&"vacation".to_string()),
            "disabled rule must not add requires"
        );
        println!("{s}");
    }

    #[test]
    fn one_liners() {
        let c = parse_condition("subject not contains \"hello world\"|bye").unwrap();
        assert!(c.not);
        assert_eq!(
            c.value,
            Values::Many(vec!["hello world".into(), "bye".into()])
        );
        assert!(parse_condition("size contains 5").is_err());
        assert!(parse_condition("subject.domain is x").is_err());
        assert!(parse_condition("list-id exists").is_ok());
        assert!(matches!(
            parse_action("forward a@b.c", false).unwrap(),
            Action::Redirect { copy: true, .. }
        ));
        assert!(parse_action("redirect nobody", false).is_ok()); // validated at compile
    }

    #[test]
    fn roundtrip_toml() {
        let set: RuleSet = toml::from_str(EXAMPLE).unwrap();
        let text = toml::to_string(&set).unwrap();
        let back: RuleSet = toml::from_str(&text).unwrap();
        assert_eq!(compile(&set).unwrap(), compile(&back).unwrap());
    }

    #[test]
    fn embedded_roundtrip() {
        let set: RuleSet = toml::from_str(EXAMPLE).unwrap();
        let script = compile(&set).unwrap().replace('\n', "\r\n");
        let back = extract(&script).unwrap().unwrap();
        assert_eq!(back.groups.len(), set.groups.len());
        assert_eq!(compile(&back).unwrap(), compile(&set).unwrap());
        assert!(extract("keep;\n").is_none());
    }

    fn rule(name: &str, folder: &str) -> Rule {
        Rule {
            name: name.into(),
            enabled: true,
            raw: None,
            match_kind: MatchKind::All,
            conditions: vec![parse_condition(&format!("subject contains {name}")).unwrap()],
            actions: vec![parse_action(&format!("fileinto {folder}"), false).unwrap()],
            stop: false,
        }
    }

    fn raw(name: &str, text: &str) -> Rule {
        Rule {
            raw: Some(text.into()),
            conditions: vec![],
            actions: vec![],
            ..rule(name, "x")
        }
    }

    fn group(name: &str, enabled: bool, rules: Vec<Rule>) -> Group {
        Group {
            name: name.into(),
            enabled,
            rules,
        }
    }

    fn requires_line(s: &str) -> &str {
        s.lines().find(|l| l.starts_with("require")).unwrap_or("")
    }

    #[test]
    fn several_groups_in_order() {
        let mut flagged = rule("Bills", "Bills");
        flagged.actions.push(parse_action("read", false).unwrap());
        let set = RuleSet {
            groups: vec![
                group("Cooking", true, vec![rule("Recipes", "Cooking")]),
                group("Money", true, vec![flagged]),
                group("Kernel", true, vec![rule("Patches", "Kernel")]),
            ],
            rules: vec![],
        };
        let s = compile(&set).unwrap();
        let pos = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle} in\n{s}"));
        assert!(pos("# ==== group: Cooking ====") < pos("# ==== group: Money ===="));
        assert!(pos("# ==== group: Money ====") < pos("# ==== group: Kernel ===="));
        assert!(pos("fileinto \"Cooking\"") < pos("fileinto \"Bills\""));
        assert_eq!(requires_line(&s), r#"require ["fileinto", "imap4flags"];"#);
        assert_eq!(without_embedded(&s).matches("require").count(), 1, "exactly one require:\n{s}");
    }

    #[test]
    fn disabled_groups_excluded() {
        let mut vac = rule("Away", "x");
        vac.actions = vec![parse_action("vacation gone", false).unwrap()];
        let set = RuleSet {
            groups: vec![
                group("On", true, vec![rule("A", "A")]),
                group("Off", false, vec![rule("B", "B"), vac]),
            ],
            rules: vec![],
        };
        let s = compile(&set).unwrap();
        assert!(s.contains("# ==== group: Off [disabled] ===="));
        assert!(s.contains("# [disabled] B"));
        assert!(!s.contains("fileinto \"B\""));
        assert!(!requires_line(&s).contains("vacation"), "{s}");
        // A disabled group still round-trips through the metadata.
        let back = extract(&s).unwrap().unwrap();
        assert!(!back.groups[1].enabled);
        assert_eq!(back.groups[1].rules.len(), 2);
    }

    #[test]
    fn require_merging_and_dedup() {
        let set = RuleSet {
            groups: vec![
                group("G1", true, vec![rule("A", "A"), raw("R1", "require [\"fileinto\", \"Body\"];\nif body :contains \"x\" { fileinto \"X\"; }\n")]),
                group("G2", true, vec![raw("R2", "require \"body\";\r\nrequire [\"copy\",\n  \"fileinto\"];\nkeep;\n")]),
            ],
            rules: vec![],
        };
        let s = compile(&set).unwrap();
        assert_eq!(requires_line(&s), r#"require ["body", "copy", "fileinto"];"#, "{s}");
        assert_eq!(without_embedded(&s).matches("require").count(), 1, "{s}");
        assert!(s.find("require").unwrap() < s.find("# ==== group: G1").unwrap());
    }

    #[test]
    fn raw_blocks_keep_position_and_hoist() {
        let text = "# keep me: require \"not-this\";\n/* require \"nor-this\"; */\nrequire [\"vacation\"]; # trailing\nif header :contains \"subject\" \"require\" {\n  vacation text:\nrequire \"inside-text\";\n.\n;\n}\n";
        let (out, exts) = hoist_requires(text);
        assert_eq!(exts, vec!["vacation"]);
        assert!(out.contains("# keep me: require \"not-this\";"));
        assert!(out.contains("/* require \"nor-this\"; */"));
        assert!(out.contains("require \"inside-text\";"), "text: block untouched");
        assert!(!out.contains("require [\"vacation\"]"));

        let set = RuleSet {
            groups: vec![group("G", true, vec![rule("Before", "B"), raw("Mine", text), rule("After", "A")])],
            rules: vec![],
        };
        let s = compile(&set).unwrap();
        assert!(s.find("fileinto \"B\"").unwrap() < s.find("# rule: Mine (raw Sieve)").unwrap());
        assert!(s.find("# rule: Mine (raw Sieve)").unwrap() < s.find("fileinto \"A\"").unwrap());
        assert_eq!(requires_line(&s), r#"require ["fileinto", "vacation"];"#);
        let back = extract(&s).unwrap().unwrap();
        assert_eq!(back.groups[0].rules[1].raw.as_deref(), Some(text), "raw text round-trips exactly");
        assert_eq!(compile(&back).unwrap(), s);
    }

    #[test]
    fn metadata_roundtrip_with_groups() {
        let mut set: RuleSet = toml::from_str(EXAMPLE).unwrap();
        set.groups[1].enabled = false;
        set.groups[2].rules.push(raw("Hand", "require \"reject\";\nif size :over 50M { reject \"too big\"; }\n"));
        let s = compile(&set).unwrap();
        let back = extract(&s).unwrap().unwrap();
        let names = |r: &RuleSet| -> Vec<(String, bool, Vec<String>)> {
            r.groups.iter().map(|g| (g.name.clone(), g.enabled, g.rules.iter().map(|r| r.name.clone()).collect())).collect()
        };
        assert_eq!(names(&back), names(&set));
        assert_eq!(compile(&back).unwrap(), s);
    }

    #[test]
    fn legacy_ungrouped_rules() {
        let old = "[[rule]]\nname = \"Old\"\nthen = [{ action = \"keep\" }]\n";
        let set: RuleSet = toml::from_str(old).unwrap();
        let g = set.clone().grouped("filters");
        assert_eq!(g.groups[0].name, "filters");
        assert!(g.rules.is_empty());
        assert!(!compile(&set).unwrap().contains("# ==== group"));
        assert!(compile(&g).unwrap().contains("# ==== group: filters ===="));
    }

    #[test]
    fn escaping() {
        assert_eq!(quote(r#"a "b" \c"#), r#""a \"b\" \\c""#);
    }
}
