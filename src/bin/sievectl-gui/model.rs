//! Editable mirror of `sievectl::rules` with plain text buffers for the UI.

use anyhow::{bail, Result};
use sievectl::rules::{Action, Condition, Group, MatchKind, Op, Rule, RuleSet, Values};

#[derive(Clone)]
pub struct UiRule {
    pub name: String,
    pub enabled: bool,
    pub any: bool,
    pub stop: bool,
    pub conds: Vec<UiCond>,
    pub actions: Vec<UiAction>,
    /// Apply to messages already in the Inbox after the next save. UI-only:
    /// not part of the compiled script.
    pub run_now: bool,
    /// Hand-written Sieve block instead of conditions/actions.
    pub raw: Option<String>,
}

#[derive(Clone)]
pub struct UiGroup {
    pub name: String,
    pub enabled: bool,
    /// UI-only: rules hidden in the sidebar.
    pub collapsed: bool,
    pub rules: Vec<UiRule>,
}

impl UiGroup {
    pub fn new(name: impl Into<String>) -> Self {
        UiGroup {
            name: name.into(),
            enabled: true,
            collapsed: false,
            rules: Vec::new(),
        }
    }

    pub fn from_group(g: &Group) -> Self {
        UiGroup {
            name: g.name.clone(),
            enabled: g.enabled,
            collapsed: false,
            rules: g.rules.iter().map(UiRule::from_rule).collect(),
        }
    }
}

#[derive(Clone)]
pub struct UiCond {
    pub field: String,
    pub op: Op,
    pub value: String,
    pub not: bool,
    pub case_sensitive: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ActKind {
    Fileinto,
    Redirect,
    Keep,
    Discard,
    Reject,
    Flag,
    Vacation,
}

impl ActKind {
    pub const ALL: [ActKind; 7] = [
        ActKind::Fileinto,
        ActKind::Flag,
        ActKind::Redirect,
        ActKind::Keep,
        ActKind::Discard,
        ActKind::Reject,
        ActKind::Vacation,
    ];
    pub fn label(self) -> &'static str {
        match self {
            ActKind::Fileinto => "Move to folder",
            ActKind::Redirect => "Forward to",
            ActKind::Keep => "Keep in Inbox",
            ActKind::Discard => "Delete (discard)",
            ActKind::Reject => "Reject with message",
            ActKind::Flag => "Set flags",
            ActKind::Vacation => "Auto-reply",
        }
    }
}

#[derive(Clone)]
pub struct UiAction {
    pub kind: ActKind,
    /// folder / address / reason / flags / vacation message
    pub text: String,
    pub create: bool,
    pub copy: bool,
    pub subject: String,
    pub days: String,
    pub from: String,
}

impl UiAction {
    pub fn new(kind: ActKind) -> Self {
        UiAction {
            kind,
            text: String::new(),
            create: false,
            copy: false,
            subject: String::new(),
            days: String::new(),
            from: String::new(),
        }
    }
}

impl UiCond {
    pub fn new() -> Self {
        UiCond {
            field: "from".into(),
            op: Op::Contains,
            value: String::new(),
            not: false,
            case_sensitive: false,
        }
    }
}

impl UiRule {
    pub fn new(n: usize) -> Self {
        UiRule {
            name: format!("New rule {n}"),
            enabled: true,
            any: false,
            stop: true,
            conds: vec![UiCond::new()],
            actions: vec![UiAction::new(ActKind::Fileinto)],
            run_now: false,
            raw: None,
        }
    }

    pub fn new_raw(n: usize) -> Self {
        UiRule {
            name: format!("Raw Sieve {n}"),
            stop: false,
            conds: Vec::new(),
            actions: Vec::new(),
            raw: Some("# Hand-written Sieve, inserted here as-is.\n# require lines are moved to the top of the script.\n".into()),
            ..UiRule::new(n)
        }
    }

    pub fn from_rule(r: &Rule) -> Self {
        let mut stop = r.stop;
        let actions = r
            .actions
            .iter()
            .filter_map(|a| {
                let mut u = UiAction::new(ActKind::Keep);
                match a {
                    Action::Fileinto {
                        folder,
                        create,
                        copy,
                    } => {
                        u.kind = ActKind::Fileinto;
                        u.text = folder.clone();
                        u.create = *create;
                        u.copy = *copy;
                    }
                    Action::Redirect { address, copy } => {
                        u.kind = ActKind::Redirect;
                        u.text = address.clone();
                        u.copy = *copy;
                    }
                    Action::Keep => u.kind = ActKind::Keep,
                    Action::Discard => u.kind = ActKind::Discard,
                    Action::Reject { reason } => {
                        u.kind = ActKind::Reject;
                        u.text = reason.clone();
                    }
                    Action::Flag { flags } => {
                        u.kind = ActKind::Flag;
                        u.text = flags.list().join(" ");
                    }
                    Action::Vacation {
                        reason,
                        subject,
                        days,
                        from,
                        addresses: _,
                    } => {
                        u.kind = ActKind::Vacation;
                        u.text = reason.clone();
                        u.subject = subject.clone().unwrap_or_default();
                        u.days = days.map(|d| d.to_string()).unwrap_or_default();
                        u.from = from.clone().unwrap_or_default();
                    }
                    Action::Stop => {
                        stop = true;
                        return None;
                    }
                }
                Some(u)
            })
            .collect();
        UiRule {
            name: r.name.clone(),
            enabled: r.enabled,
            any: r.match_kind == MatchKind::Any,
            stop,
            conds: r
                .conditions
                .iter()
                .map(|c| UiCond {
                    field: c.field.clone(),
                    op: c.op,
                    value: c.value.list().join(" | "),
                    not: c.not,
                    case_sensitive: c.case_sensitive,
                })
                .collect(),
            actions,
            run_now: false,
            raw: r.raw.clone(),
        }
    }

    pub fn to_rule(&self) -> Result<Rule> {
        if let Some(raw) = &self.raw {
            return Ok(Rule {
                name: self.name.trim().to_string(),
                enabled: self.enabled,
                raw: Some(raw.clone()),
                match_kind: MatchKind::All,
                conditions: Vec::new(),
                actions: Vec::new(),
                stop: false,
            });
        }
        let split = |s: &str, sep: char| -> Vec<String> {
            s.split(sep)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        };
        let one = |v: Vec<String>| {
            if v.len() == 1 {
                Values::One(v[0].clone())
            } else {
                Values::Many(v)
            }
        };
        let conditions = self
            .conds
            .iter()
            .map(|c| Condition {
                field: c.field.trim().to_string(),
                op: c.op,
                value: if c.op == Op::Exists {
                    Values::default()
                } else {
                    one(split(&c.value, '|'))
                },
                not: c.not,
                case_sensitive: c.case_sensitive,
            })
            .collect();
        let mut actions = Vec::new();
        for a in &self.actions {
            let opt = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_string());
            actions.push(match a.kind {
                ActKind::Fileinto => Action::Fileinto {
                    folder: a.text.trim().into(),
                    create: a.create,
                    copy: a.copy,
                },
                ActKind::Redirect => Action::Redirect {
                    address: a.text.trim().into(),
                    copy: a.copy,
                },
                ActKind::Keep => Action::Keep,
                ActKind::Discard => Action::Discard,
                ActKind::Reject => Action::Reject {
                    reason: a.text.clone(),
                },
                ActKind::Flag => Action::Flag {
                    flags: one(split(&a.text, ' ')),
                },
                ActKind::Vacation => {
                    if a.text.trim().is_empty() {
                        bail!("auto-reply needs a message");
                    }
                    let days = match opt(&a.days) {
                        Some(d) => Some(
                            d.parse::<u32>()
                                .map_err(|_| anyhow::anyhow!("days must be a number"))?,
                        ),
                        None => None,
                    };
                    Action::Vacation {
                        reason: a.text.clone(),
                        subject: opt(&a.subject),
                        days,
                        from: opt(&a.from),
                        addresses: Values::default(),
                    }
                }
            });
        }
        Ok(Rule {
            name: self.name.trim().to_string(),
            enabled: self.enabled,
            raw: None,
            match_kind: if self.any {
                MatchKind::Any
            } else {
                MatchKind::All
            },
            conditions,
            actions,
            stop: self.stop,
        })
    }
}

pub fn to_ruleset(groups: &[UiGroup]) -> Result<RuleSet> {
    let mut out = Vec::new();
    for g in groups {
        let mut rules = Vec::new();
        for (i, r) in g.rules.iter().enumerate() {
            rules.push(r.to_rule().map_err(|e| {
                anyhow::anyhow!("group {:?}, rule #{} {:?}: {e}", g.name, i + 1, r.name)
            })?);
        }
        out.push(Group {
            name: g.name.trim().to_string(),
            enabled: g.enabled,
            rules,
        });
    }
    Ok(RuleSet {
        groups: out,
        rules: Vec::new(),
    })
}

/// (field key, label) shown in the condition field picker.
pub const FIELDS: &[(&str, &str)] = &[
    ("from", "From"),
    ("from.domain", "From domain"),
    ("from.localpart", "From user (before @)"),
    ("to", "To"),
    ("cc", "Cc"),
    ("to-or-cc", "To or Cc"),
    ("to.domain", "To domain"),
    ("reply-to", "Reply-To"),
    ("sender", "Sender"),
    ("subject", "Subject"),
    ("list-id", "List-Id (mailing list)"),
    ("body", "Body text"),
    ("size", "Message size"),
    ("envelope-from", "Envelope sender"),
    ("envelope-to", "Envelope recipient"),
    ("envelope-to.localpart", "Envelope recipient user"),
];

pub fn field_label(f: &str) -> Option<&'static str> {
    FIELDS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(f))
        .map(|(_, l)| *l)
}

pub fn op_label(o: Op) -> &'static str {
    match o {
        Op::Is => "is",
        Op::Contains => "contains",
        Op::Matches => "matches (* ?)",
        Op::Regex => "matches regex",
        Op::Exists => "exists",
        Op::Over => "is larger than",
        Op::Under => "is smaller than",
    }
}

pub const TEXT_OPS: [Op; 5] = [Op::Contains, Op::Is, Op::Matches, Op::Regex, Op::Exists];
pub const SIZE_OPS: [Op; 2] = [Op::Over, Op::Under];
pub const FLAGS: &[(&str, &str)] = &[
    ("\\Seen", "Read"),
    ("\\Flagged", "Flagged"),
    ("\\Answered", "Answered"),
    ("\\Deleted", "Deleted"),
    ("$Junk", "Junk"),
];
