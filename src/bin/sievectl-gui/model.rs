//! Editable mirror of `sievectl::rules` with plain text buffers for the UI.

use anyhow::{bail, Result};
use sievectl::rules::{Action, Condition, MatchKind, Op, Rule, RuleSet, Values};

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
        }
    }

    pub fn to_rule(&self) -> Result<Rule> {
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

pub fn to_ruleset(rules: &[UiRule]) -> Result<RuleSet> {
    let mut v = Vec::new();
    for (i, r) in rules.iter().enumerate() {
        v.push(
            r.to_rule()
                .map_err(|e| anyhow::anyhow!("rule #{} {:?}: {e}", i + 1, r.name))?,
        );
    }
    Ok(RuleSet { rules: v })
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
