//! Evaluating rules against a message outside the server.
//!
//! Sieve only runs at delivery, so to apply rules to mail that's already in
//! a mailbox, a client works out locally what the rules would do, with
//! Sieve's matching semantics, and then carries it out itself. This module
//! is the protocol-neutral part: callers supply each message's headers,
//! addresses, size and (if a rule needs it) body text, and get back what
//! should happen to it. Vera Colander drives it over IMAP; Rock Mail over
//! JMAP.

use crate::{classify, Action, Condition, FieldKind, MatchKind, Op, Rule};
use anyhow::{Context, Result};
use std::collections::BTreeSet;

/// The folder name Sieve uses for the Inbox.
pub const INBOX: &str = "INBOX";

/// A message as the rules see it.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub size: u64,
    /// (lower-case name, decoded unfolded value), in order.
    pub headers: Vec<(String, String)>,
    /// (lower-case header name, address) for every address in address
    /// headers.
    pub addresses: Vec<(String, String)>,
    /// Text of the message (only needed when [`Evaluator::needs_body`]).
    pub body: String,
}

impl Message {
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Addresses in an address header. Headers not given as addresses (e.g.
    /// Delivered-To) fall back to the bare `<addr>` or the text.
    pub fn address_values(&self, name: &str) -> Vec<String> {
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

/// What the rules would do to one message.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    /// Flags to add (`\Seen`, `\Flagged`, `$Junk`…).
    pub flags: Vec<String>,
    /// Folders to copy it into (it also stays where it is, or moves).
    pub copies: Vec<String>,
    /// Folder to move it to (Trash for a discard).
    pub move_to: Option<String>,
    pub forwards: Vec<String>,
}

impl Outcome {
    pub fn is_noop(&self) -> bool {
        self.flags.is_empty() && self.copies.is_empty() && self.move_to.is_none() && self.forwards.is_empty()
    }

    /// "Forward to … · Mark read · Move to Lists"
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.forwards.is_empty() {
            parts.push(format!("Forward to {}", self.forwards.join(", ")));
        }
        if !self.flags.is_empty() {
            let names: Vec<&str> = self.flags.iter().map(|f| flag_name(f)).collect();
            parts.push(format!("Mark {}", names.join(", ")));
        }
        for c in &self.copies {
            parts.push(format!("Copy to {c}"));
        }
        if let Some(t) = &self.move_to {
            parts.push(format!("Move to {t}"));
        }
        parts.join(" · ")
    }
}

pub fn flag_name(f: &str) -> &str {
    match f.to_ascii_lowercase().as_str() {
        "\\seen" => "read",
        "\\flagged" => "flagged",
        "\\answered" => "answered",
        "\\deleted" => "deleted",
        "\\draft" => "draft",
        _ => f,
    }
}

/// Rules compiled for evaluation, in order.
pub struct Evaluator<'a> {
    rules: Vec<CompiledRule<'a>>,
    /// Some rule tests the body, so messages need their text.
    pub needs_body: bool,
    /// Some rules are raw Sieve, which can't be evaluated here.
    pub has_raw: bool,
}

impl<'a> Evaluator<'a> {
    /// Enabled rules only; pass them in script order.
    pub fn new(rules: &'a [Rule]) -> Result<Self> {
        let rules: Vec<CompiledRule> = rules.iter().map(CompiledRule::new).collect::<Result<_>>()?;
        Ok(Evaluator {
            needs_body: rules.iter().any(|r| r.needs_body),
            has_raw: rules.iter().any(|r| r.rule.raw.is_some()),
            rules,
        })
    }

    /// Whether rule `i` matches (for tests and "why" displays).
    pub fn rule_matches(&self, i: usize, m: &Message) -> bool {
        self.rules.get(i).is_some_and(|r| r.matches(m))
    }

    /// What the rules would do to `m`. `exists` says whether a folder (by
    /// Sieve name) exists; missing folders with "create" are added to
    /// `create`. Things the user should know go into `notes`.
    pub fn plan(
        &self,
        m: &Message,
        exists: &dyn Fn(&str) -> bool,
        trash: Option<&str>,
        create: &mut BTreeSet<String>,
        notes: &mut BTreeSet<String>,
    ) -> Outcome {
        let mut p = Outcome::default();
        let mut implicit_keep = true;
        let mut explicit_keep = false;
        let mut folders: Vec<String> = Vec::new();
        'rules: for r in &self.rules {
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
                        if !exists(folder) {
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
                        notes.insert("Reject isn't applied to existing mail (it would bounce old messages).".into());
                    }
                    Action::Vacation { .. } => {
                        notes.insert(
                            "Auto-reply isn't applied to existing mail (it would reply to old senders).".into(),
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
                    notes.insert("No Trash folder found, so messages the rule would delete stay in the Inbox.".into());
                }
            }
        }
        p
    }
}

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
        Ok(CompiledRule { rule, conds, needs_body })
    }

    fn matches(&self, m: &Message) -> bool {
        if self.rule.raw.is_some() {
            return false; // hand-written Sieve can't be evaluated here
        }
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
        Ok(CompiledCond { kind, part, op: c.op, not: c.not, case_sensitive: c.case_sensitive, values, regexes })
    }

    fn test(&self, m: &Message) -> bool {
        self.not != self.test_inner(m)
    }

    fn test_inner(&self, m: &Message) -> bool {
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
                    FieldKind::Address(hs) => {
                        hs.iter().flat_map(|h| m.address_values(h)).map(|a| self.address_part(&a)).collect()
                    }
                    FieldKind::Envelope(e) => {
                        let src: &[&str] = if *e == "from" {
                            &["return-path"]
                        } else {
                            &["delivered-to", "x-original-to", "envelope-to"]
                        };
                        src.iter().flat_map(|h| m.address_values(h)).map(|a| self.address_part(&a)).collect()
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
        let fold = |s: &str| if self.case_sensitive { s.to_string() } else { s.to_ascii_lowercase() };
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
pub fn parse_size(v: &str) -> Option<u64> {
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
pub fn glob(hay: &str, pat: &str) -> bool {
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

    #[test]
    fn sizes() {
        assert_eq!(parse_size("500K"), Some(500 * 1024));
        assert_eq!(parse_size(" 2m "), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("123"), Some(123));
        assert_eq!(parse_size("lots"), None);
    }
}
