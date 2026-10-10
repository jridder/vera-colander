//! Per-OS config file: profiles with host/user/etc. Passwords come from
//! $SIEVE_PASSWORD, a `password_command`, or an interactive prompt.

use crate::managesieve::TlsMode;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub profile: BTreeMap<String, Profile>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Profile {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub tls: Option<TlsMode>,
    pub ca_file: Option<PathBuf>,
    pub password_command: Option<String>,
    pub allow_plaintext: Option<bool>,
    /// Default script name for `deploy`
    pub script: Option<String>,
    /// Default rules file for `deploy` / `rule` commands
    pub rules: Option<PathBuf>,
}

/// Linux: ~/.config/sievectl/config.toml
/// macOS: ~/Library/Application Support/sievectl/config.toml
/// Windows: %APPDATA%\sievectl\config\config.toml
pub fn path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SIEVECTL_CONFIG") {
        return Some(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "sievectl").map(|d| d.config_dir().join("config.toml"))
}

pub fn load_profile(name: &str) -> Result<Profile> {
    let Some(p) = path() else { return Ok(Profile::default()) };
    if !p.exists() {
        if name != "default" {
            bail!("profile {name:?} requested but {} does not exist", p.display());
        }
        return Ok(Profile::default());
    }
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    let mut cfg: ConfigFile = toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
    match cfg.profile.remove(name) {
        Some(pr) => Ok(pr),
        None if name == "default" => Ok(Profile::default()),
        None => bail!("profile {name:?} not found in {}", p.display()),
    }
}

pub fn password(profile: &Profile, user: &str, host: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SIEVE_PASSWORD") {
        return Ok(p);
    }
    if let Some(cmd) = &profile.password_command {
        let out = if cfg!(windows) {
            Command::new("cmd").args(["/C", cmd]).output()
        } else {
            Command::new("sh").args(["-c", cmd]).output()
        }
        .with_context(|| format!("running password_command {cmd:?}"))?;
        if !out.status.success() {
            bail!("password_command failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        let s = String::from_utf8(out.stdout).context("password_command output is not UTF-8")?;
        return Ok(s.lines().next().unwrap_or("").to_string());
    }
    rpassword::prompt_password(format!("Password for {user}@{host}: ")).context("reading password")
}

pub const TEMPLATE: &str = r#"# sievectl configuration. Select a profile with -P NAME (default: "default").

[profile.default]
host = "mail.example.com"
user = "me@example.com"
# port = 4190
# tls = "starttls"            # starttls | implicit | none
# ca_file = "/path/to/ca.pem" # for a private/self-signed CA
# script = "sievectl"         # script name used by `deploy`
# rules = "/path/to/rules.toml"
#
# Optional: fetch the password from a manager instead of prompting.
#   macOS:   password_command = "security find-generic-password -s sievectl -w"
#   Linux:   password_command = "pass show mail/sieve"
#   Windows: password_command = "powershell -NoProfile -Command \"(Get-StoredCredential -Target sievectl).GetNetworkCredential().Password\""
# Or set SIEVE_PASSWORD in the environment.
"#;
