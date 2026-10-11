//! Minimal SMTP submission (RFC 6409) over implicit TLS, for redirecting
//! existing messages the way Sieve's `redirect` does: the message is resent
//! unchanged to a new envelope recipient.

use crate::managesieve::{tcp_connect, tls_wrap, Stream};
use anyhow::{bail, Context, Result};
use base64::Engine;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub struct Submission {
    r: BufReader<Box<dyn Stream>>,
}

impl Submission {
    pub fn login(
        host: &str,
        port: u16,
        ca_file: Option<&Path>,
        user: &str,
        pass: &str,
    ) -> Result<Submission> {
        let tcp = tcp_connect(host, port)?;
        let tls = tls_wrap(Box::new(tcp), host, ca_file)?;
        let mut s = Submission {
            r: BufReader::new(tls),
        };
        s.reply(220).context("SMTP greeting")?;
        s.cmd("EHLO vera-colander", 250)?;
        let ir = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        s.cmd(&format!("AUTH PLAIN {ir}"), 235)
            .context("SMTP login failed")?;
        Ok(s)
    }

    /// Send `message` (raw RFC 5322 bytes) from envelope `from` to `to`.
    pub fn redirect(&mut self, from: &str, to: &str, message: &[u8]) -> Result<()> {
        self.cmd(&format!("MAIL FROM:<{from}>"), 250)?;
        self.cmd(&format!("RCPT TO:<{to}>"), 250)
            .with_context(|| format!("recipient {to}"))?;
        self.cmd("DATA", 354)?;
        let mut out = Vec::with_capacity(message.len() + 64);
        for line in message.split_inclusive(|&b| b == b'\n') {
            let body = line.strip_suffix(b"\n").unwrap_or(line);
            let body = body.strip_suffix(b"\r").unwrap_or(body);
            if body.first() == Some(&b'.') {
                out.push(b'.');
            }
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
        let w = self.r.get_mut();
        w.write_all(&out)?;
        w.flush()?;
        self.reply(250).context("sending message")?;
        Ok(())
    }

    pub fn quit(mut self) {
        let _ = self.cmd("QUIT", 221);
    }

    fn cmd(&mut self, line: &str, want: u16) -> Result<String> {
        let w = self.r.get_mut();
        w.write_all(line.as_bytes())?;
        w.write_all(b"\r\n")?;
        w.flush()?;
        self.reply(want)
    }

    /// Read a (possibly multi-line) reply; Err unless its code is `want`.
    fn reply(&mut self, want: u16) -> Result<String> {
        let mut text = String::new();
        loop {
            let mut l = String::new();
            if self.r.read_line(&mut l)? == 0 {
                bail!("server closed the connection");
            }
            let code: u16 = l.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
            text.push_str(l.get(4..).unwrap_or("").trim_end());
            text.push(' ');
            if l.as_bytes().get(3) != Some(&b'-') {
                if code != want {
                    bail!("server said {code} {}", text.trim());
                }
                return Ok(text);
            }
        }
    }
}
