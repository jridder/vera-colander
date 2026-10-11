use sievectl::{config, managesieve, rules};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use managesieve::{Client, ConnectOptions, TlsMode};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(
    name = "sievectl",
    version,
    about = "ManageSieve client and Sieve rule builder"
)]
struct Cli {
    #[command(flatten)]
    conn: ConnArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct ConnArgs {
    /// Config profile
    #[arg(
        short = 'P',
        long,
        global = true,
        env = "SIEVECTL_PROFILE",
        default_value = "default"
    )]
    profile: String,
    /// ManageSieve server
    #[arg(short = 'H', long, global = true, env = "SIEVECTL_HOST")]
    host: Option<String>,
    /// Port [default: 4190]
    #[arg(short, long, global = true)]
    port: Option<u16>,
    /// Login user
    #[arg(short, long, global = true, env = "SIEVECTL_USER")]
    user: Option<String>,
    /// TLS mode [default: starttls]
    #[arg(long, global = true, value_enum)]
    tls: Option<TlsMode>,
    /// Extra CA certificate(s) in PEM format
    #[arg(long, global = true)]
    ca_file: Option<PathBuf>,
    /// Allow sending the password without TLS
    #[arg(long, global = true)]
    allow_plaintext: bool,
    /// Print protocol traffic to stderr (password redacted)
    #[arg(long, global = true)]
    debug: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show server capabilities and supported Sieve extensions
    Caps,
    /// List scripts on the server (* = active)
    #[command(alias = "ls")]
    List,
    /// Download a script
    Get {
        name: String,
        /// Write to file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Upload a Sieve script file ("-" for stdin)
    Put {
        name: String,
        file: PathBuf,
        #[arg(short, long)]
        activate: bool,
    },
    /// Validate a Sieve script file on the server without storing it
    Check { file: PathBuf },
    /// Make a script the active one
    Activate { name: String },
    /// Deactivate all scripts
    Deactivate,
    /// Delete a script
    #[command(alias = "rm")]
    Delete {
        name: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Rename a script
    Rename { old: String, new: String },
    /// Edit a script on the server in $EDITOR (validated before upload)
    Edit {
        name: String,
        #[arg(short, long)]
        activate: bool,
    },
    /// Write an example rules file
    Init {
        #[arg(default_value = "rules.toml")]
        file: PathBuf,
    },
    /// Compile a rules file to Sieve (offline)
    Compile {
        rules: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Compile a rules file, validate it on the server, and upload it
    Deploy {
        rules: Option<PathBuf>,
        /// Script name on the server [default: profile `script` or "vera-colander"]
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        activate: bool,
        /// Validate on the server and print the script, but don't upload
        #[arg(long)]
        dry_run: bool,
        /// Upload even if the server copy is identical
        #[arg(long)]
        force: bool,
    },
    /// Download a script made by sievectl and write its rules back to a TOML file
    Pull {
        /// Script name on the server [default: "vera-colander"]
        name: Option<String>,
        #[arg(default_value = "rules.toml")]
        file: PathBuf,
        #[arg(short, long)]
        force: bool,
    },
    /// Manage groups of rules in a rules file
    #[command(subcommand)]
    Group(GroupCmd),
    /// Manage rules in a rules file
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Store the password in the system keychain (shared with the GUI)
    Login {
        /// Remove the stored password instead
        #[arg(long)]
        forget: bool,
    },
    /// Show the config file location, or create it with --init
    Config {
        #[arg(long)]
        init: bool,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Add an empty group
    Add {
        name: String,
        /// Insert at position (1 = first) instead of appending
        #[arg(long)]
        at: Option<usize>,
        /// Create it disabled
        #[arg(long)]
        disabled: bool,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
    /// List groups and their rules
    #[command(alias = "ls")]
    List {
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
    /// Remove a group and all its rules
    #[command(alias = "rm")]
    Remove {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
    /// Enable a group
    Enable {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
    /// Disable a group (kept in the file, its rules omitted from the script)
    Disable {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
    /// Move a group to a new position (1 = first)
    Move {
        name: String,
        to: usize,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum RuleCmd {
    /// Add a rule.  Example:
    ///   sievectl rule add -g Work -n GitHub --if "from.domain is github.com" --then "fileinto GitHub" --stop
    Add {
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        #[arg(short, long)]
        name: String,
        /// Group to add it to (created if missing) [default: "Rules"]
        #[arg(short, long)]
        group: Option<String>,
        /// Condition: "FIELD [not] OP [VALUE|VALUE...]" (repeatable)
        #[arg(long = "if", value_name = "COND")]
        conds: Vec<String>,
        /// Action: fileinto|copy|redirect|forward|keep|discard|reject|flag|read|vacation|stop ARG (repeatable)
        #[arg(long = "then", value_name = "ACTION", required = true)]
        actions: Vec<String>,
        /// Match if ANY condition is true (default: ALL)
        #[arg(long)]
        any: bool,
        /// Stop processing further rules after this one matches
        #[arg(long)]
        stop: bool,
        /// Create target folders if they don't exist (fileinto :create)
        #[arg(long)]
        create: bool,
        /// Insert at position (1 = first) instead of appending
        #[arg(long)]
        at: Option<usize>,
    },
    /// List rules (grouped)
    #[command(alias = "ls")]
    List {
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Only this group
        #[arg(short, long)]
        group: Option<String>,
    },
    /// Show the Sieve generated for one rule
    Show {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Group holding the rule, if the name isn't unique
        #[arg(short, long)]
        group: Option<String>,
    },
    /// Remove a rule
    #[command(alias = "rm")]
    Remove {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Group holding the rule, if the name isn't unique
        #[arg(short, long)]
        group: Option<String>,
    },
    /// Enable a rule
    Enable {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Group holding the rule, if the name isn't unique
        #[arg(short, long)]
        group: Option<String>,
    },
    /// Disable a rule (kept in the file, omitted from the script)
    Disable {
        name: String,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Group holding the rule, if the name isn't unique
        #[arg(short, long)]
        group: Option<String>,
    },
    /// Move a rule to a new position within its group (1 = first)
    Move {
        name: String,
        to: usize,
        #[arg(short, long = "file")]
        file: Option<PathBuf>,
        /// Group holding the rule, if the name isn't unique
        #[arg(short, long)]
        group: Option<String>,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

struct Ctx {
    args: ConnArgs,
    profile: config::Profile,
}

impl Ctx {
    fn rules_path(&self, given: Option<PathBuf>) -> PathBuf {
        given
            .or_else(|| self.profile.rules.clone())
            .unwrap_or_else(|| PathBuf::from("rules.toml"))
    }

    fn connect(&self) -> Result<Client> {
        self.connect_opt(None)
    }

    fn connect_with(&self, pw: &str) -> Result<Client> {
        self.connect_opt(Some(pw))
    }

    fn connect_opt(&self, pw: Option<&str>) -> Result<Client> {
        let a = &self.args;
        let p = &self.profile;
        let host = a.host.clone().or_else(|| p.host.clone()).context(
            "no server given: use --host or set host in the config file (see `sievectl config --init`)",
        )?;
        let user = a
            .user
            .clone()
            .or_else(|| p.user.clone())
            .context("no user given: use --user or config")?;
        let tls = a.tls.or(p.tls).unwrap_or(TlsMode::Starttls);
        let opts = ConnectOptions {
            host: host.clone(),
            port: a.port.or(p.port).unwrap_or(4190),
            tls,
            ca_file: a.ca_file.clone().or_else(|| p.ca_file.clone()),
            debug: a.debug,
        };
        let mut c = Client::connect(&opts)?;
        if !c.tls_active && !(a.allow_plaintext || p.allow_plaintext.unwrap_or(false)) {
            bail!("refusing to send password without TLS (pass --allow-plaintext to override)");
        }
        let pass = match pw {
            Some(pw) => pw.to_string(),
            None => config::password(p, &user, &host)?,
        };
        c.authenticate_plain(&user, &pass)?;
        Ok(c)
    }
}

fn read_input(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn confirm(q: &str) -> bool {
    eprint!("{q} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).is_ok() && matches!(s.trim(), "y" | "Y" | "yes")
}

fn print_warnings(w: Option<String>) {
    if let Some(w) = w {
        eprintln!("warning: {}", w.trim());
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let profile = config::load_profile(&cli.conn.profile)?;
    let ctx = Ctx {
        args: cli.conn,
        profile,
    };

    match cli.cmd {
        Cmd::Caps => {
            let c = ctx.connect()?;
            for (k, v) in &c.caps.0 {
                match v {
                    Some(v) => println!("{k:<16} {v}"),
                    None => println!("{k}"),
                }
            }
            c.logout();
        }
        Cmd::List => {
            let mut c = ctx.connect()?;
            for (name, active) in c.list_scripts()? {
                println!("{} {name}", if active { "*" } else { " " });
            }
            c.logout();
        }
        Cmd::Get { name, output } => {
            let mut c = ctx.connect()?;
            let s = c.get_script(&name)?;
            c.logout();
            match output {
                Some(p) => std::fs::write(&p, s)?,
                None => print!("{s}"),
            }
        }
        Cmd::Put {
            name,
            file,
            activate,
        } => {
            let script = read_input(&file)?;
            let mut c = ctx.connect()?;
            print_warnings(
                c.check_script(&script)
                    .context("script rejected by server")?,
            );
            c.put_script(&name, &script)?;
            eprintln!("uploaded {name} ({} bytes)", script.len());
            if activate {
                c.set_active(&name)?;
                eprintln!("activated {name}");
            }
            c.logout();
        }
        Cmd::Check { file } => {
            let script = read_input(&file)?;
            let mut c = ctx.connect()?;
            let r = c.check_script(&script);
            c.logout();
            print_warnings(r.context("script rejected by server")?);
            eprintln!("OK");
        }
        Cmd::Activate { name } => {
            let mut c = ctx.connect()?;
            c.set_active(&name)?;
            c.logout();
            eprintln!("activated {name}");
        }
        Cmd::Deactivate => {
            let mut c = ctx.connect()?;
            c.set_active("")?;
            c.logout();
            eprintln!("no script is active now");
        }
        Cmd::Delete { name, yes } => {
            if !yes && !confirm(&format!("Delete script {name:?} from the server?")) {
                bail!("aborted");
            }
            let mut c = ctx.connect()?;
            c.delete_script(&name)?;
            c.logout();
            eprintln!("deleted {name}");
        }
        Cmd::Rename { old, new } => {
            let mut c = ctx.connect()?;
            c.rename_script(&old, &new)?;
            c.logout();
        }
        Cmd::Edit { name, activate } => edit(&ctx, &name, activate)?,
        Cmd::Init { file } => {
            if file.exists() {
                bail!("{} already exists", file.display());
            }
            std::fs::write(&file, rules::EXAMPLE)?;
            eprintln!("wrote {}", file.display());
        }
        Cmd::Compile { rules: r, output } => {
            let path = ctx.rules_path(r);
            let script = rules::compile(&rules::load(&path)?)?;
            match output {
                Some(p) => std::fs::write(&p, script)?,
                None => print!("{script}"),
            }
        }
        Cmd::Deploy {
            rules: r,
            name,
            activate,
            dry_run,
            force,
        } => {
            let path = ctx.rules_path(r);
            let script = rules::compile(&rules::load(&path)?)?;
            let name = name
                .or_else(|| ctx.profile.script.clone())
                .unwrap_or_else(|| rules::SCRIPT_NAME.into());
            let mut c = ctx.connect()?;
            let have = c.caps.sieve_extensions();
            if !have.is_empty() {
                let missing: Vec<_> = rules::required(&script)
                    .into_iter()
                    .filter(|r| !have.iter().any(|h| h.eq_ignore_ascii_case(r)))
                    .collect();
                if !missing.is_empty() {
                    eprintln!("warning: server does not advertise: {}", missing.join(", "));
                }
            }
            print_warnings(
                c.check_script(&script)
                    .context("server rejected the generated script")?,
            );
            if dry_run {
                print!("{script}");
                eprintln!("dry run: script is valid, nothing uploaded");
                c.logout();
                return Ok(());
            }
            let existing = c.list_scripts()?;
            let current = existing.iter().find(|(n, _)| *n == name);
            let same = match current {
                Some(_) if !force => {
                    c.get_script(&name)?.replace("\r\n", "\n") == script.replace("\r\n", "\n")
                }
                _ => false,
            };
            if same {
                eprintln!("{name} is unchanged on the server");
            } else {
                print_warnings(c.put_script(&name, &script)?);
                let set = rules::load(&path)?;
                eprintln!(
                    "uploaded {name} ({} groups, {} rules)",
                    set.groups.len(),
                    set.all_rules().count()
                );
            }
            if activate && !current.is_some_and(|(_, a)| *a) {
                c.set_active(&name)?;
                eprintln!("activated {name}");
            } else if !activate && !current.is_some_and(|(_, a)| *a) {
                eprintln!("note: {name} is not the active script (use --activate)");
            }
            c.logout();
        }
        Cmd::Pull { name, file, force } => {
            // `pull rules.toml` means the file, not a script called that.
            let (name, file) = match name {
                Some(n) if n.ends_with(".toml") && file == Path::new("rules.toml") => {
                    (rules::SCRIPT_NAME.to_string(), PathBuf::from(n))
                }
                n => (n.unwrap_or_else(|| rules::SCRIPT_NAME.into()), file),
            };
            if file.exists() && !force {
                bail!("{} exists (use --force to overwrite)", file.display());
            }
            let mut c = ctx.connect()?;
            let script = c.get_script(&name)?;
            c.logout();
            let set = rules::extract(&script)
                .with_context(|| {
                    format!("{name} was not generated by sievectl (no embedded rules)")
                })??
                .grouped(&name);
            rules::save(&file, &set)?;
            eprintln!(
                "wrote {} groups, {} rules to {}",
                set.groups.len(),
                set.all_rules().count(),
                file.display()
            );
        }
        Cmd::Group(gc) => group_cmd(&ctx, gc)?,
        Cmd::Rule(rc) => rule_cmd(&ctx, rc)?,
        Cmd::Login { forget } => {
            let host = ctx
                .args
                .host
                .clone()
                .or_else(|| ctx.profile.host.clone())
                .context("no server given")?;
            let user = ctx
                .args
                .user
                .clone()
                .or_else(|| ctx.profile.user.clone())
                .context("no user given")?;
            let entry = config::keychain_entry(&user, &host)?;
            if forget {
                entry.delete_credential()?;
                eprintln!("removed stored password for {user}@{host}");
            } else {
                let p = rpassword::prompt_password(format!("Password for {user}@{host}: "))?;
                let c = ctx.connect_with(&p)?;
                c.logout();
                entry.set_password(&p)?;
                eprintln!("password verified and stored in the system keychain");
            }
        }
        Cmd::Config { init } => {
            let p = config::path().context("could not determine config directory")?;
            if init {
                if p.exists() {
                    bail!("{} already exists", p.display());
                }
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d)?;
                }
                std::fs::write(&p, config::TEMPLATE)?;
                eprintln!("wrote {}", p.display());
            } else {
                println!("{}", p.display());
                if !p.exists() {
                    eprintln!("(does not exist yet; create it with `sievectl config --init`)");
                }
            }
        }
    }
    Ok(())
}

fn find_group(set: &rules::RuleSet, name: &str) -> Result<usize> {
    set.group_index(name)
        .with_context(|| format!("no group named {name:?}"))
}

/// (group index, rule index) of a rule, optionally within one group.
fn find(set: &rules::RuleSet, name: &str, group: Option<&str>) -> Result<(usize, usize)> {
    let only = group.map(|g| find_group(set, g)).transpose()?;
    let hits: Vec<(usize, usize)> = set
        .groups
        .iter()
        .enumerate()
        .filter(|(gi, _)| only.is_none_or(|o| o == *gi))
        .flat_map(|(gi, g)| {
            g.rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.name.eq_ignore_ascii_case(name))
                .map(move |(ri, _)| (gi, ri))
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => bail!("no rule named {name:?}"),
        _ => bail!("several groups have a rule named {name:?}; pick one with --group"),
    }
}

fn group_cmd(ctx: &Ctx, gc: GroupCmd) -> Result<()> {
    match gc {
        GroupCmd::Add {
            name,
            at,
            disabled,
            file,
        } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load_or_empty(&path)?.grouped(rules::DEFAULT_GROUP);
            if set.group_index(&name).is_some() {
                bail!("a group named {name:?} already exists");
            }
            let mut g = rules::Group::new(name.clone());
            g.enabled = !disabled;
            let pos = at
                .map(|n| n.clamp(1, set.groups.len() + 1) - 1)
                .unwrap_or(set.groups.len());
            set.groups.insert(pos, g);
            rules::save(&path, &set)?;
            eprintln!("added group {name:?} as #{} in {}", pos + 1, path.display());
        }
        GroupCmd::List { file } => {
            let set = rules::load(&ctx.rules_path(file))?;
            for (i, g) in set.groups.iter().enumerate() {
                println!(
                    "{:>3}. {}  ({} rule{}){}",
                    i + 1,
                    g.name,
                    g.rules.len(),
                    if g.rules.len() == 1 { "" } else { "s" },
                    if g.enabled { "" } else { "  [disabled]" }
                );
            }
        }
        GroupCmd::Remove { name, file } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load(&path)?;
            let g = set.groups.remove(find_group(&set, &name)?);
            rules::save(&path, &set)?;
            eprintln!("removed group {name:?} and its {} rules", g.rules.len());
        }
        GroupCmd::Enable { name, file } => set_group_enabled(ctx, file, &name, true)?,
        GroupCmd::Disable { name, file } => set_group_enabled(ctx, file, &name, false)?,
        GroupCmd::Move { name, to, file } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load(&path)?;
            let g = set.groups.remove(find_group(&set, &name)?);
            let pos = to.clamp(1, set.groups.len() + 1) - 1;
            set.groups.insert(pos, g);
            rules::save(&path, &set)?;
            eprintln!("moved group {name:?} to #{}", pos + 1);
        }
    }
    Ok(())
}

fn set_group_enabled(ctx: &Ctx, file: Option<PathBuf>, name: &str, on: bool) -> Result<()> {
    let path = ctx.rules_path(file);
    let mut set = rules::load(&path)?;
    let i = find_group(&set, name)?;
    set.groups[i].enabled = on;
    rules::save(&path, &set)?;
    eprintln!("{} group {name:?}", if on { "enabled" } else { "disabled" });
    Ok(())
}

fn rule_cmd(ctx: &Ctx, rc: RuleCmd) -> Result<()> {
    match rc {
        RuleCmd::Add {
            file,
            name,
            group,
            conds,
            actions,
            any,
            stop,
            create,
            at,
        } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load_or_empty(&path)?.grouped(rules::DEFAULT_GROUP);
            let group = group.unwrap_or_else(|| rules::DEFAULT_GROUP.into());
            let gi = match set.group_index(&group) {
                Some(i) => i,
                None => {
                    set.groups.push(rules::Group::new(group.clone()));
                    eprintln!("created group {group:?}");
                    set.groups.len() - 1
                }
            };
            if set.groups[gi]
                .rules
                .iter()
                .any(|r| r.name.eq_ignore_ascii_case(&name))
            {
                bail!("group {group:?} already has a rule named {name:?}");
            }
            let mut rule = rules::Rule {
                name,
                enabled: true,
                raw: None,
                match_kind: if any {
                    rules::MatchKind::Any
                } else {
                    rules::MatchKind::All
                },
                conditions: conds
                    .iter()
                    .map(|c| rules::parse_condition(c))
                    .collect::<Result<_>>()?,
                actions: Vec::new(),
                stop,
            };
            for a in &actions {
                match rules::parse_action(a, create)? {
                    rules::Action::Stop => rule.stop = true,
                    act => rule.actions.push(act),
                }
            }
            let snippet = rules::compile_rule(&rule, &mut Default::default())?;
            let g = &mut set.groups[gi];
            let pos = at
                .map(|n| n.clamp(1, g.rules.len() + 1) - 1)
                .unwrap_or(g.rules.len());
            g.rules.insert(pos, rule);
            let gname = g.name.clone();
            rules::save(&path, &set)?;
            eprintln!(
                "added as rule #{} of group {gname:?} in {}:",
                pos + 1,
                path.display()
            );
            print!("{snippet}");
        }
        RuleCmd::List { file, group } => {
            let set = rules::load(&ctx.rules_path(file))?;
            let only = group.as_deref().map(|g| find_group(&set, g)).transpose()?;
            for (gi, g) in set.groups.iter().enumerate() {
                if only.is_some_and(|o| o != gi) {
                    continue;
                }
                println!("{}{}", g.name, if g.enabled { "" } else { "  [disabled]" });
                for (i, r) in g.rules.iter().enumerate() {
                    println!(
                        "  {:>3}. {}{}{}{}",
                        i + 1,
                        r.name,
                        if r.raw.is_some() { "  (raw Sieve)" } else { "" },
                        if r.enabled { "" } else { "  [disabled]" },
                        if r.stop { "  (stop)" } else { "" }
                    );
                }
            }
        }
        RuleCmd::Show { name, file, group } => {
            let set = rules::load(&ctx.rules_path(file))?;
            let (gi, ri) = find(&set, &name, group.as_deref())?;
            let r = &set.groups[gi].rules[ri];
            print!("{}", rules::compile_rule(r, &mut Default::default())?);
        }
        RuleCmd::Remove { name, file, group } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load(&path)?;
            let (gi, ri) = find(&set, &name, group.as_deref())?;
            set.groups[gi].rules.remove(ri);
            rules::save(&path, &set)?;
            eprintln!("removed {name:?} from group {:?}", set.groups[gi].name);
        }
        RuleCmd::Enable { name, file, group } => set_enabled(ctx, file, &name, group, true)?,
        RuleCmd::Disable { name, file, group } => set_enabled(ctx, file, &name, group, false)?,
        RuleCmd::Move {
            name,
            to,
            file,
            group,
        } => {
            let path = ctx.rules_path(file);
            let mut set = rules::load(&path)?;
            let (gi, ri) = find(&set, &name, group.as_deref())?;
            let g = &mut set.groups[gi];
            let r = g.rules.remove(ri);
            let pos = to.clamp(1, g.rules.len() + 1) - 1;
            g.rules.insert(pos, r);
            rules::save(&path, &set)?;
            eprintln!("moved {name:?} to #{}", pos + 1);
        }
    }
    Ok(())
}

fn set_enabled(
    ctx: &Ctx,
    file: Option<PathBuf>,
    name: &str,
    group: Option<String>,
    on: bool,
) -> Result<()> {
    let path = ctx.rules_path(file);
    let mut set = rules::load(&path)?;
    let (gi, ri) = find(&set, name, group.as_deref())?;
    set.groups[gi].rules[ri].enabled = on;
    rules::save(&path, &set)?;
    eprintln!("{} {name:?}", if on { "enabled" } else { "disabled" });
    Ok(())
}

fn editor_command() -> Vec<String> {
    let e = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(windows) {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    e.split_whitespace().map(String::from).collect()
}

fn edit(ctx: &Ctx, name: &str, activate: bool) -> Result<()> {
    let mut c = ctx.connect()?;
    let exists = c.list_scripts()?.iter().any(|(n, _)| n == name);
    let original = if exists {
        c.get_script(name)?
    } else {
        eprintln!("{name} does not exist yet; starting a new script");
        "require [\"fileinto\"];\n\n".to_string()
    };
    let tmp = tempfile::Builder::new()
        .prefix("sievectl-")
        .suffix(".sieve")
        .tempfile()?;
    std::fs::write(tmp.path(), &original)?;
    let ed = editor_command();
    loop {
        let st = Command::new(&ed[0])
            .args(&ed[1..])
            .arg(tmp.path())
            .status()
            .with_context(|| format!("launching editor {:?} (set $EDITOR)", ed[0]))?;
        if !st.success() {
            bail!("editor exited with {st}");
        }
        let edited = std::fs::read_to_string(tmp.path())?;
        if edited == original {
            eprintln!("no changes");
            break;
        }
        match c.check_script(&edited) {
            Ok(w) => {
                print_warnings(w);
                c.put_script(name, &edited)?;
                eprintln!("uploaded {name}");
                break;
            }
            Err(e) => {
                eprintln!("server rejected the script:\n{e}");
                if !confirm("Edit again?") {
                    let (_, kept) = tmp.keep()?;
                    bail!(
                        "aborted, server copy unchanged; your edit is saved at {}",
                        kept.display()
                    );
                }
            }
        }
    }
    if activate {
        c.set_active(name)?;
        eprintln!("activated {name}");
    }
    c.logout();
    Ok(())
}
