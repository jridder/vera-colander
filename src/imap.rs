//! Just enough IMAP (RFC 9051 / 3501) to list a user's mail folders, so the
//! GUI can offer them as `fileinto` targets. Implicit TLS, SASL PLAIN, LIST.

use crate::managesieve::{tcp_connect, tls_wrap, Stream};
use anyhow::{bail, Context, Result};
use base64::Engine;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

/// Selectable folders, INBOX first, then sorted case-insensitively. Names are
/// UTF-8 (modified UTF-7 decoded), as Sieve's `fileinto` expects.
pub fn list_folders(
    host: &str,
    port: u16,
    ca_file: Option<&Path>,
    user: &str,
    pass: &str,
) -> Result<Vec<String>> {
    let tcp = tcp_connect(host, port)?;
    let tls = tls_wrap(Box::new(tcp), host, ca_file)?;
    let mut c = Conn {
        r: BufReader::new(tls),
    };

    let greet = c.line().context("IMAP greeting")?;
    if !starts_with_ci(&greet, "* OK") {
        bail!("unexpected IMAP greeting: {}", text(&greet));
    }

    c.write(b"a1 AUTHENTICATE PLAIN\r\n")?;
    let cont = c.line()?;
    if !cont.starts_with(b"+") {
        bail!("IMAP AUTHENTICATE PLAIN refused: {}", text(&cont));
    }
    let ir = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
    c.write(format!("{ir}\r\n").as_bytes())?;
    c.tagged("a1").context("IMAP login failed")?;

    c.write(b"a2 LIST \"\" \"*\"\r\n")?;
    let lines = c.tagged("a2").context("IMAP LIST")?;
    let _ = c.write(b"a3 LOGOUT\r\n");

    let mut folders: Vec<String> = lines.iter().filter_map(|l| parse_list(l)).collect();
    folders.sort_by_key(|f| (!f.eq_ignore_ascii_case("INBOX"), f.to_lowercase()));
    folders.dedup();
    Ok(folders)
}

struct Conn {
    r: BufReader<Box<dyn Stream>>,
}

impl Conn {
    fn write(&mut self, b: &[u8]) -> Result<()> {
        let w = self.r.get_mut();
        w.write_all(b)?;
        w.flush()?;
        Ok(())
    }

    /// One response line with any `{n}` literals inlined as quoted strings,
    /// so the result can be tokenised without further I/O.
    fn line(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut l = Vec::new();
            if self.r.read_until(b'\n', &mut l)? == 0 {
                bail!("server closed the connection");
            }
            while matches!(l.last(), Some(b'\r' | b'\n')) {
                l.pop();
            }
            match literal_len(&l) {
                Some((start, n)) => {
                    out.extend_from_slice(&l[..start]);
                    let mut lit = vec![0; n];
                    self.r.read_exact(&mut lit)?;
                    out.push(b'"');
                    for b in lit {
                        if b == b'"' || b == b'\\' {
                            out.push(b'\\');
                        }
                        out.push(b);
                    }
                    out.push(b'"');
                }
                None => {
                    out.extend_from_slice(&l);
                    return Ok(out);
                }
            }
        }
    }

    /// Untagged lines up to the completion of `tag`; Err unless it is OK.
    fn tagged(&mut self, tag: &str) -> Result<Vec<Vec<u8>>> {
        let mut lines = Vec::new();
        loop {
            let l = self.line()?;
            if starts_with_ci(&l, &format!("{tag} ")) {
                let rest = &l[tag.len() + 1..];
                if starts_with_ci(rest, "OK") {
                    return Ok(lines);
                }
                bail!("server said {}", text(rest));
            }
            if starts_with_ci(&l, "* BYE") {
                bail!("server said {}", text(&l[2..]));
            }
            lines.push(l);
        }
    }
}

/// `{123}` or `{123+}` at the end of a line: (offset of `{`, length).
fn literal_len(l: &[u8]) -> Option<(usize, usize)> {
    let l2 = l.strip_suffix(b"}")?;
    let start = l2.iter().rposition(|&b| b == b'{')?;
    let digits = &l2[start + 1..];
    let digits = digits.strip_suffix(b"+").unwrap_or(digits);
    let n = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some((start, n))
}

/// `* LIST (\HasNoChildren) "/" "Lists/Debian"` → `Some("Lists/Debian")`;
/// None for other lines and for `\Noselect` / `\NonExistent` folders.
fn parse_list(l: &[u8]) -> Option<String> {
    let mut t = Tokens { s: l, i: 0 };
    if t.next()? != "*" || !t.next()?.eq_ignore_ascii_case("LIST") {
        return None;
    }
    let flags = t.paren()?;
    if flags.iter().any(|f| {
        f.eq_ignore_ascii_case("\\Noselect") || f.eq_ignore_ascii_case("\\NonExistent")
    }) {
        return None;
    }
    t.next()?; // hierarchy delimiter (or NIL)
    let name = t.next()?;
    Some(decode_mutf7(&name).unwrap_or(name))
}

struct Tokens<'a> {
    s: &'a [u8],
    i: usize,
}

impl Tokens<'_> {
    fn skip_ws(&mut self) {
        while self.s.get(self.i) == Some(&b' ') {
            self.i += 1;
        }
    }

    /// Next atom or quoted string.
    fn next(&mut self) -> Option<String> {
        self.skip_ws();
        let mut v = Vec::new();
        if self.s.get(self.i) == Some(&b'"') {
            self.i += 1;
            loop {
                match *self.s.get(self.i)? {
                    b'"' => {
                        self.i += 1;
                        break;
                    }
                    b'\\' => {
                        self.i += 1;
                        v.push(*self.s.get(self.i)?);
                    }
                    b => v.push(b),
                }
                self.i += 1;
            }
        } else {
            while let Some(&b) = self.s.get(self.i) {
                if b == b' ' || b == b'(' || b == b')' {
                    break;
                }
                v.push(b);
                self.i += 1;
            }
            if v.is_empty() {
                return None;
            }
        }
        Some(String::from_utf8_lossy(&v).into_owned())
    }

    /// A parenthesised list of atoms.
    fn paren(&mut self) -> Option<Vec<String>> {
        self.skip_ws();
        if self.s.get(self.i) != Some(&b'(') {
            return None;
        }
        self.i += 1;
        let mut v = Vec::new();
        loop {
            self.skip_ws();
            if self.s.get(self.i)? == &b')' {
                self.i += 1;
                return Some(v);
            }
            v.push(self.next()?);
        }
    }
}

/// IMAP modified UTF-7 (RFC 3501 5.1.3): `&AOk-t&AOk-` → `été`.
fn decode_mutf7(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut it = s.split('&');
    out.push_str(it.next()?);
    for part in it {
        let (enc, rest) = part.split_once('-')?;
        if enc.is_empty() {
            out.push('&');
        } else {
            let b64 = enc.replace(',', "/");
            let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(b64.trim_end_matches('='))
                .ok()?;
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            out.push_str(&String::from_utf16(&units).ok()?);
        }
        out.push_str(rest);
    }
    Some(out)
}

fn starts_with_ci(l: &[u8], p: &str) -> bool {
    l.len() >= p.len() && l[..p.len()].eq_ignore_ascii_case(p.as_bytes())
}

fn text(l: &[u8]) -> String {
    String::from_utf8_lossy(l).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_lines() {
        assert_eq!(
            parse_list(br#"* LIST (\HasNoChildren) "/" "Lists/Debian""#).as_deref(),
            Some("Lists/Debian")
        );
        assert_eq!(parse_list(br#"* LIST () "." INBOX"#).as_deref(), Some("INBOX"));
        assert_eq!(parse_list(br#"* LIST (\Noselect \HasChildren) "/" "Lists""#), None);
        assert_eq!(
            parse_list(br#"* LIST (\HasNoChildren \Sent) "/" "Sent Items""#).as_deref(),
            Some("Sent Items")
        );
        assert_eq!(
            parse_list(br#"* LIST () NIL "Say \"hi\"""#).as_deref(),
            Some("Say \"hi\"")
        );
        assert_eq!(parse_list(b"* OK still here"), None);
    }

    #[test]
    fn literals() {
        assert_eq!(literal_len(br#"* LIST () "/" {11}"#), Some((14, 11)));
        assert_eq!(literal_len(b"* LIST () \"/\" {5+}"), Some((14, 5)));
        assert_eq!(literal_len(b"* LIST () \"/\" Foo"), None);
    }

    #[test]
    fn modified_utf7() {
        assert_eq!(decode_mutf7("INBOX").as_deref(), Some("INBOX"));
        assert_eq!(decode_mutf7("&AOk-t&AOk-").as_deref(), Some("été"));
        assert_eq!(decode_mutf7("Tom &- Jerry").as_deref(), Some("Tom & Jerry"));
        assert_eq!(decode_mutf7("&ZeVnLIqe-").as_deref(), Some("日本語"));
    }
}
