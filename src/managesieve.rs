//! Minimal ManageSieve (RFC 5804) client: STARTTLS / implicit TLS, SASL PLAIN,
//! and the script management commands.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rustls_pki_types::{pem::PemObject, CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Plain TCP, then STARTTLS (standard, port 4190)
    Starttls,
    /// TLS from the first byte
    Implicit,
    /// No TLS at all (requires --allow-plaintext to send a password)
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Atom(String),
    Str(String),
    LParen,
    RParen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    No,
    Bye,
}

#[derive(Debug)]
pub struct Response {
    pub lines: Vec<Vec<Token>>,
    pub status: Status,
    pub code: Option<String>,
    pub message: Option<String>,
}

impl Response {
    pub fn describe(&self) -> String {
        let mut s = format!("{:?}", self.status).to_uppercase();
        if let Some(c) = &self.code {
            s.push_str(&format!(" ({c})"));
        }
        if let Some(m) = &self.message {
            s.push_str(&format!(": {}", m.trim()));
        }
        s
    }
    fn ok(self) -> Result<Response> {
        match self.status {
            Status::Ok => Ok(self),
            _ => Err(anyhow!("server said {}", self.describe())),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Capabilities(pub Vec<(String, Option<String>)>);

impl Capabilities {
    fn from_lines(lines: &[Vec<Token>]) -> Self {
        let mut v = Vec::new();
        for l in lines {
            let mut it = l.iter().filter_map(|t| match t {
                Token::Str(s) | Token::Atom(s) => Some(s.clone()),
                _ => None,
            });
            if let Some(k) = it.next() {
                v.push((k.to_ascii_uppercase(), it.next()));
            }
        }
        Capabilities(v)
    }
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }
    pub fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    pub fn sasl(&self) -> Vec<String> {
        self.get("SASL")
            .map(|s| {
                s.split_whitespace()
                    .map(|m| m.to_ascii_uppercase())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn sieve_extensions(&self) -> Vec<String> {
        self.get("SIEVE")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    pub ca_file: Option<PathBuf>,
    pub debug: bool,
}

enum Arg<'a> {
    Atom(&'a str),
    Str(&'a str),
    Lit(&'a [u8]),
}

pub struct Client {
    r: Option<BufReader<Box<dyn Stream>>>,
    pub caps: Capabilities,
    pub tls_active: bool,
    debug: bool,
}

impl Client {
    pub fn connect(o: &ConnectOptions) -> Result<Client> {
        let tcp = tcp_connect(&o.host, o.port)?;

        let mut stream: Box<dyn Stream> = Box::new(tcp);
        let mut tls_active = false;
        if o.tls == TlsMode::Implicit {
            stream = tls_wrap(stream, &o.host, o.ca_file.as_deref())?;
            tls_active = true;
        }
        let mut c = Client {
            r: Some(BufReader::new(stream)),
            caps: Capabilities::default(),
            tls_active,
            debug: o.debug,
        };
        let greet = c.read_response()?.ok().context("server greeting")?;
        c.caps = Capabilities::from_lines(&greet.lines);

        if o.tls == TlsMode::Starttls {
            if !c.caps.has("STARTTLS") {
                bail!("server does not offer STARTTLS (try --tls implicit or --tls none)");
            }
            c.send(&[Arg::Atom("STARTTLS")])?;
            c.read_response()?.ok().context("STARTTLS")?;
            let inner = c.r.take().unwrap().into_inner();
            c.r = Some(BufReader::new(tls_wrap(
                inner,
                &o.host,
                o.ca_file.as_deref(),
            )?));
            c.tls_active = true;
            // RFC 5804 2.2: server re-issues capabilities after TLS negotiation.
            let caps = c
                .read_response()?
                .ok()
                .context("post-STARTTLS capabilities")?;
            c.caps = Capabilities::from_lines(&caps.lines);
        }
        Ok(c)
    }

    pub fn authenticate_plain(&mut self, user: &str, pass: &str) -> Result<()> {
        let mechs = self.caps.sasl();
        if !mechs.iter().any(|m| m == "PLAIN") {
            bail!(
                "server does not offer SASL PLAIN (offers: {})",
                mechs.join(" ")
            );
        }
        let ir = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        self.send(&[Arg::Atom("AUTHENTICATE"), Arg::Str("PLAIN"), Arg::Str(&ir)])?;
        self.read_response()?
            .ok()
            .context("authentication failed")?;
        Ok(())
    }

    /// Returns (name, is_active)
    pub fn list_scripts(&mut self) -> Result<Vec<(String, bool)>> {
        self.send(&[Arg::Atom("LISTSCRIPTS")])?;
        let r = self.read_response()?.ok()?;
        Ok(r.lines
            .iter()
            .filter_map(|l| match l.first() {
                Some(Token::Str(n)) => Some((
                    n.clone(),
                    matches!(l.get(1), Some(Token::Atom(a)) if a.eq_ignore_ascii_case("ACTIVE")),
                )),
                _ => None,
            })
            .collect())
    }

    pub fn get_script(&mut self, name: &str) -> Result<String> {
        self.send(&[Arg::Atom("GETSCRIPT"), Arg::Str(name)])?;
        let r = self.read_response()?.ok()?;
        r.lines
            .iter()
            .flatten()
            .find_map(|t| match t {
                Token::Str(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("empty GETSCRIPT response"))
    }

    /// Validate a script on the server. Ok(Some(warnings)) / Ok(None) on success,
    /// Err with the server's error text on failure.
    pub fn check_script(&mut self, content: &str) -> Result<Option<String>> {
        self.send(&[Arg::Atom("CHECKSCRIPT"), Arg::Lit(content.as_bytes())])?;
        let r = self.read_response()?;
        match r.status {
            Status::Ok => Ok(warnings(&r)),
            _ => bail!("{}", r.message.clone().unwrap_or_else(|| r.describe())),
        }
    }

    pub fn put_script(&mut self, name: &str, content: &str) -> Result<Option<String>> {
        self.send(&[
            Arg::Atom("PUTSCRIPT"),
            Arg::Str(name),
            Arg::Lit(content.as_bytes()),
        ])?;
        let r = self.read_response()?;
        match r.status {
            Status::Ok => Ok(warnings(&r)),
            _ => bail!("{}", r.message.clone().unwrap_or_else(|| r.describe())),
        }
    }

    /// Empty name deactivates all scripts.
    pub fn set_active(&mut self, name: &str) -> Result<()> {
        self.send(&[Arg::Atom("SETACTIVE"), Arg::Str(name)])?;
        self.read_response()?.ok().map(|_| ())
    }

    pub fn delete_script(&mut self, name: &str) -> Result<()> {
        self.send(&[Arg::Atom("DELETESCRIPT"), Arg::Str(name)])?;
        self.read_response()?.ok().map(|_| ())
    }

    pub fn rename_script(&mut self, old: &str, new: &str) -> Result<()> {
        self.send(&[Arg::Atom("RENAMESCRIPT"), Arg::Str(old), Arg::Str(new)])?;
        self.read_response()?.ok().map(|_| ())
    }

    pub fn logout(mut self) {
        if self.send(&[Arg::Atom("LOGOUT")]).is_ok() {
            let _ = self.read_response();
        }
    }

    // ---- wire format -------------------------------------------------------

    fn rd(&mut self) -> &mut BufReader<Box<dyn Stream>> {
        self.r.as_mut().expect("stream present")
    }

    fn send(&mut self, args: &[Arg]) -> Result<()> {
        let mut out = Vec::new();
        for (i, a) in args.iter().enumerate() {
            if i > 0 {
                out.push(b' ');
            }
            match a {
                Arg::Atom(s) => out.extend_from_slice(s.as_bytes()),
                Arg::Str(s) if s.len() <= 1024 && !s.contains(['\r', '\n', '\0']) => {
                    out.push(b'"');
                    for ch in s.bytes() {
                        if ch == b'"' || ch == b'\\' {
                            out.push(b'\\');
                        }
                        out.push(ch);
                    }
                    out.push(b'"');
                }
                Arg::Str(s) => push_literal(&mut out, s.as_bytes()),
                Arg::Lit(b) => push_literal(&mut out, b),
            }
        }
        out.extend_from_slice(b"\r\n");
        if self.debug {
            let shown = match args.first() {
                Some(Arg::Atom(a)) if a.eq_ignore_ascii_case("AUTHENTICATE") => {
                    "AUTHENTICATE \"PLAIN\" <redacted>".to_string()
                }
                _ => String::from_utf8_lossy(&out).trim_end().to_string(),
            };
            eprintln!("C: {shown}");
        }
        let w = self.rd().get_mut();
        w.write_all(&out)?;
        w.flush()?;
        Ok(())
    }

    fn peek(&mut self) -> Result<u8> {
        let buf = self.rd().fill_buf()?;
        buf.first()
            .copied()
            .ok_or_else(|| anyhow!("server closed the connection"))
    }

    fn bump(&mut self) -> Result<u8> {
        let b = self.peek()?;
        self.rd().consume(1);
        Ok(b)
    }

    fn read_line(&mut self) -> Result<Vec<Token>> {
        let mut toks = Vec::new();
        loop {
            match self.peek()? {
                b' ' | b'\t' => {
                    self.bump()?;
                }
                b'\r' => {
                    self.bump()?;
                    if self.bump()? != b'\n' {
                        bail!("protocol error: CR without LF");
                    }
                    break;
                }
                b'\n' => {
                    self.bump()?;
                    break;
                }
                b'"' => {
                    self.bump()?;
                    let s = self.read_quoted()?;
                    toks.push(Token::Str(s));
                }
                b'{' => {
                    self.bump()?;
                    let s = self.read_literal()?;
                    toks.push(Token::Str(s));
                }
                b'(' => {
                    self.bump()?;
                    toks.push(Token::LParen);
                }
                b')' => {
                    self.bump()?;
                    toks.push(Token::RParen);
                }
                _ => {
                    let a = self.read_atom()?;
                    toks.push(Token::Atom(a));
                }
            }
        }
        if self.debug {
            eprintln!("S: {toks:?}");
        }
        Ok(toks)
    }

    fn read_quoted(&mut self) -> Result<String> {
        let mut v = Vec::new();
        loop {
            match self.bump()? {
                b'"' => break,
                b'\\' => v.push(self.bump()?),
                b'\r' | b'\n' => bail!("protocol error: newline in quoted string"),
                b => v.push(b),
            }
        }
        Ok(String::from_utf8_lossy(&v).into_owned())
    }

    fn read_literal(&mut self) -> Result<String> {
        let mut n: usize = 0;
        loop {
            match self.bump()? {
                d @ b'0'..=b'9' => {
                    n = n
                        .checked_mul(10)
                        .and_then(|n| n.checked_add((d - b'0') as usize))
                        .ok_or_else(|| anyhow!("literal too large"))?
                }
                b'+' => {}
                b'}' => break,
                b => bail!("protocol error: bad literal byte {b:#x}"),
            }
        }
        if self.bump()? != b'\r' || self.bump()? != b'\n' {
            bail!("protocol error: literal not followed by CRLF");
        }
        let mut buf = vec![0u8; n];
        self.rd().read_exact(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    fn read_atom(&mut self) -> Result<String> {
        let mut v = Vec::new();
        loop {
            match self.peek()? {
                b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' => break,
                b => {
                    v.push(b);
                    self.bump()?;
                }
            }
        }
        Ok(String::from_utf8_lossy(&v).into_owned())
    }

    fn read_response(&mut self) -> Result<Response> {
        let mut lines = Vec::new();
        loop {
            let line = self.read_line()?;
            let status = match line.first() {
                Some(Token::Atom(a)) => match a.to_ascii_uppercase().as_str() {
                    "OK" => Some(Status::Ok),
                    "NO" => Some(Status::No),
                    "BYE" => Some(Status::Bye),
                    _ => None,
                },
                _ => None,
            };
            let Some(status) = status else {
                lines.push(line);
                continue;
            };
            let mut i = 1;
            let mut code = None;
            if line.get(1) == Some(&Token::LParen) {
                let mut depth = 0;
                let mut parts = Vec::new();
                for t in &line[1..] {
                    i += 1;
                    match t {
                        Token::LParen => {
                            depth += 1;
                            if depth > 1 {
                                parts.push("(".to_string());
                            }
                        }
                        Token::RParen => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                            parts.push(")".to_string());
                        }
                        Token::Atom(a) => parts.push(a.clone()),
                        Token::Str(s) => parts.push(format!("\"{s}\"")),
                    }
                }
                code = Some(parts.join(" "));
            }
            let message = line[i.min(line.len())..].iter().find_map(|t| match t {
                Token::Str(s) => Some(s.clone()),
                _ => None,
            });
            return Ok(Response {
                lines,
                status,
                code,
                message,
            });
        }
    }
}

fn warnings(r: &Response) -> Option<String> {
    match &r.code {
        Some(c) if c.to_ascii_uppercase().starts_with("WARNINGS") => {
            Some(r.message.clone().unwrap_or_default())
        }
        _ => None,
    }
}

fn push_literal(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("{{{}+}}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
}

/// TCP connection with connect/read/write timeouts.
pub(crate) fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", host))?
        .collect();
    let mut last = None;
    let mut tcp = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(15)) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        anyhow!(
            "could not connect to {}:{}: {}",
            host,
            port,
            last.map(|e| e.to_string())
                .unwrap_or_else(|| "no addresses".into())
        )
    })?;
    tcp.set_read_timeout(Some(Duration::from_secs(60)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(60)))?;
    Ok(tcp)
}

pub(crate) fn tls_wrap(
    stream: Box<dyn Stream>,
    host: &str,
    ca_file: Option<&Path>,
) -> Result<Box<dyn Stream>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(p) = ca_file {
        for cert in CertificateDer::pem_file_iter(p)
            .with_context(|| format!("reading CA file {}", p.display()))?
        {
            roots.add(cert?)?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name)?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).with_context(|| {
            format!("TLS handshake with {host} failed (private CA? use --ca-file)")
        })?;
    }
    Ok(Box::new(tls))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Scripted fake server: sends greeting, then for each expected command
    /// prefix replies with the canned response.
    fn fake_server(script: Vec<(&'static str, &'static str)>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            w.write_all(b"\"IMPLEMENTATION\" \"Fake\"\r\n\"SASL\" \"PLAIN LOGIN\"\r\n\"SIEVE\" \"fileinto vacation\"\r\nOK \"ready\"\r\n").unwrap();
            for (expect, reply) in script {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                // swallow non-synchronizing literal payloads
                if let Some(pos) = line.find("{") {
                    let n: usize = line[pos + 1..line.find("+}").unwrap()].parse().unwrap();
                    let mut buf = vec![0; n + 2];
                    r.read_exact(&mut buf).unwrap();
                }
                assert!(line.starts_with(expect), "got {line:?}, expected {expect}");
                w.write_all(reply.as_bytes()).unwrap();
            }
        });
        port
    }

    /// A tiny stateful ManageSieve server: stores uploads, tracks the active
    /// script, serves GETSCRIPT/LISTSCRIPTS/DELETESCRIPT from that state.
    fn stateful_server(initial: Vec<(&'static str, String, bool)>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut scripts: Vec<(String, String)> =
                initial.iter().map(|(n, c, _)| (n.to_string(), c.clone())).collect();
            let mut active: Option<String> = initial
                .iter()
                .find(|(_, _, a)| *a)
                .map(|(n, _, _)| n.to_string());
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            w.write_all(b"\"IMPLEMENTATION\" \"Fake\"\r\n\"SASL\" \"PLAIN\"\r\n\"SIEVE\" \"fileinto imap4flags mailbox body copy vacation\"\r\nOK\r\n").unwrap();
            let quoted = |line: &str, n: usize| -> String {
                line.split('"').nth(1 + 2 * n).unwrap_or("").to_string()
            };
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let mut lit = String::new();
                if let Some(pos) = line.find('{') {
                    let n: usize = line[pos + 1..line.find("+}").unwrap()].parse().unwrap();
                    let mut buf = vec![0; n + 2];
                    r.read_exact(&mut buf).unwrap();
                    lit = String::from_utf8(buf[..n].to_vec()).unwrap();
                }
                let cmd = line.split_whitespace().next().unwrap_or("").to_string();
                let reply = match cmd.as_str() {
                    "AUTHENTICATE" | "CHECKSCRIPT" => "OK\r\n".to_string(),
                    "LISTSCRIPTS" => {
                        let mut o = String::new();
                        for (n, _) in &scripts {
                            let a = if active.as_deref() == Some(n) { " ACTIVE" } else { "" };
                            o.push_str(&format!("\"{n}\"{a}\r\n"));
                        }
                        o + "OK\r\n"
                    }
                    "GETSCRIPT" => {
                        let n = quoted(&line, 0);
                        let c = &scripts.iter().find(|(x, _)| *x == n).unwrap().1;
                        format!("{{{}}}\r\n{c}\r\nOK\r\n", c.len())
                    }
                    "PUTSCRIPT" => {
                        let n = quoted(&line, 0);
                        scripts.retain(|(x, _)| *x != n);
                        scripts.push((n, lit));
                        "OK\r\n".into()
                    }
                    "SETACTIVE" => {
                        active = Some(quoted(&line, 0)).filter(|n| !n.is_empty());
                        "OK\r\n".into()
                    }
                    "DELETESCRIPT" => {
                        let n = quoted(&line, 0);
                        if active.as_deref() == Some(n.as_str()) {
                            "NO (ACTIVE) \"active\"\r\n".into()
                        } else {
                            scripts.retain(|(x, _)| *x != n);
                            "OK\r\n".into()
                        }
                    }
                    "LOGOUT" => {
                        let _ = w.write_all(b"OK\r\n");
                        break;
                    }
                    _ => format!("NO \"unexpected {}\"\r\n", line.trim()),
                };
                w.write_all(reply.as_bytes()).unwrap();
            }
        });
        port
    }

    /// First connect with two existing scripts → import → save the single
    /// "vera-colander" script → it's active → delete the old scripts.
    #[test]
    fn one_script_migration_end_to_end() {
        use crate::rules::{self, SCRIPT_NAME};
        let legacy: rules::RuleSet = toml::from_str(
            "[[rule]]\nname = \"Kernel\"\nif = [{ field = \"list-id\", op = \"contains\", value = \"kernel\" }]\nthen = [{ action = \"fileinto\", folder = \"Kernel\" }]\n",
        )
        .unwrap();
        let foreign = "require [\"fileinto\", \"body\"];\r\nif body :contains \"recipe\" { fileinto \"Cooking\"; }\r\n";
        let initial = vec![
            ("NYT Cooking", foreign.to_string(), true),
            ("Kernel Updates", rules::compile(&legacy).unwrap(), false),
        ];
        // SIEVE_E2E=host:port:user:pass runs this against a real server
        // (plain TCP, e.g. a local Dovecot); otherwise an in-process fake.
        let real = std::env::var("SIEVE_E2E").ok();
        let (host, port, user, pass) = match &real {
            Some(spec) => {
                let v: Vec<&str> = spec.splitn(4, ':').collect();
                (v[0].to_string(), v[1].parse().unwrap(), v[2].to_string(), v[3].to_string())
            }
            None => ("127.0.0.1".into(), stateful_server(initial.clone()), "u".into(), "p".into()),
        };
        let mut c = Client::connect(&ConnectOptions {
            host,
            port,
            tls: TlsMode::None,
            ca_file: None,
            debug: false,
        })
        .unwrap();
        c.authenticate_plain(&user, &pass).unwrap();
        if real.is_some() {
            // Start from the same state as the fake: just the two old scripts.
            c.set_active("").unwrap();
            for (n, _) in c.list_scripts().unwrap() {
                c.delete_script(&n).unwrap();
            }
            for (n, content, active) in &initial {
                c.put_script(n, content).unwrap();
                if *active {
                    c.set_active(n).unwrap();
                }
            }
        }

        // Import every script as groups (active one first, others disabled).
        let mut listed = c.list_scripts().unwrap();
        listed.sort_by_key(|(_, a)| !*a);
        let mut set = rules::RuleSet::default();
        for (name, active) in &listed {
            let content = c.get_script(name).unwrap();
            set.groups.extend(rules::import_script(name, &content, *active));
        }
        assert_eq!(set.groups.len(), 2);
        assert!(set.groups[0].enabled && set.groups[0].rules[0].raw.is_some());
        assert_eq!(set.groups[1].name, "Kernel Updates");
        assert!(!set.groups[1].enabled, "inactive script imports disabled");
        set.groups[1].enabled = true;

        // Save: CHECKSCRIPT, PUTSCRIPT "vera-colander", SETACTIVE "vera-colander".
        let script = rules::compile(&set).unwrap();
        c.check_script(&script).unwrap();
        c.put_script(SCRIPT_NAME, &script).unwrap();
        c.set_active(SCRIPT_NAME).unwrap();
        let listed = c.list_scripts().unwrap();
        assert!(listed.contains(&(SCRIPT_NAME.to_string(), true)), "{listed:?}");

        // What's on the server reopens as the same groups and script.
        let stored = c.get_script(SCRIPT_NAME).unwrap().replace("\r\n", "\n");
        let back = rules::extract(&stored).unwrap().unwrap();
        assert_eq!(back.groups.len(), 2);
        assert_eq!(rules::compile(&back).unwrap(), script);
        let body = rules::without_embedded(&stored);
        assert_eq!(body.matches("require").count(), 1, "{body}");
        assert!(body.contains(r#"require ["body", "fileinto"];"#), "{body}");

        // Offer accepted: delete the old scripts.
        c.delete_script("NYT Cooking").unwrap();
        c.delete_script("Kernel Updates").unwrap();
        assert_eq!(c.list_scripts().unwrap(), vec![(SCRIPT_NAME.to_string(), true)]);
        c.logout();
    }

    #[test]
    fn full_session() {
        let port = fake_server(vec![
            ("AUTHENTICATE \"PLAIN\"", "OK\r\n"),
            (
                "LISTSCRIPTS",
                "\"main\" ACTIVE\r\n\"old \\\"one\\\"\"\r\nOK\r\n",
            ),
            ("GETSCRIPT \"main\"", "{12}\r\nkeep;\r\nstop;\r\nOK\r\n"),
            ("CHECKSCRIPT {", "NO \"line 1: unknown command 'foo'\"\r\n"),
            ("PUTSCRIPT \"x\" {", "OK (WARNINGS) \"line 2: unused\"\r\n"),
            ("SETACTIVE \"x\"", "NO (NONEXISTENT) \"nope\"\r\n"),
        ]);
        let mut c = Client::connect(&ConnectOptions {
            host: "127.0.0.1".into(),
            port,
            tls: TlsMode::None,
            ca_file: None,
            debug: false,
        })
        .unwrap();
        assert_eq!(c.caps.sasl(), vec!["PLAIN", "LOGIN"]);
        assert_eq!(c.caps.sieve_extensions(), vec!["fileinto", "vacation"]);
        c.authenticate_plain("u", "p").unwrap();
        assert_eq!(
            c.list_scripts().unwrap(),
            vec![("main".into(), true), ("old \"one\"".into(), false)]
        );
        assert_eq!(c.get_script("main").unwrap(), "keep;\r\nstop;");
        let e = c.check_script("foo;").unwrap_err().to_string();
        assert!(e.contains("unknown command"));
        assert_eq!(
            c.put_script("x", "keep;").unwrap().as_deref(),
            Some("line 2: unused")
        );
        let e = c.set_active("x").unwrap_err().to_string();
        assert!(e.contains("NONEXISTENT"), "{e}");
    }
}
