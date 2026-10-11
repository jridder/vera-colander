//! Just enough IMAP (RFC 9051 / 3501) to list a user's folders and to apply
//! rules to messages already in a mailbox: implicit TLS, SASL PLAIN, LIST,
//! SELECT, UID FETCH/STORE/COPY/MOVE.

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
    let mut s = Session::login(host, port, ca_file, user, pass)?;
    let folders = s.list()?.into_iter().map(|f| f.name).collect();
    s.logout();
    Ok(folders)
}

pub struct Folder {
    pub name: String,
    /// Has the `\Trash` special-use attribute (RFC 6154).
    pub trash: bool,
}

/// One message from a fetch: UID, RFC822.SIZE, and the header (or the whole
/// message when the body was requested).
pub struct Fetched {
    pub uid: u32,
    pub size: u64,
    pub data: Vec<u8>,
}

pub struct Session {
    r: BufReader<Box<dyn Stream>>,
    tag: u32,
    caps: Vec<String>,
}

impl Session {
    pub fn login(
        host: &str,
        port: u16,
        ca_file: Option<&Path>,
        user: &str,
        pass: &str,
    ) -> Result<Session> {
        let tcp = tcp_connect(host, port)?;
        let tls = tls_wrap(Box::new(tcp), host, ca_file)?;
        let mut s = Session {
            r: BufReader::new(tls),
            tag: 0,
            caps: Vec::new(),
        };
        let greet = s.read().context("IMAP greeting")?;
        if !greet.is_status("*", "OK") {
            bail!("unexpected IMAP greeting: {}", greet.text);
        }
        let tag = s.next_tag();
        s.write(format!("{tag} AUTHENTICATE PLAIN\r\n").as_bytes())?;
        let cont = s.read()?;
        if cont.toks.first().map(Tok::atom) != Some("+") {
            bail!("IMAP AUTHENTICATE PLAIN refused: {}", cont.text);
        }
        let ir = base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        s.write(format!("{ir}\r\n").as_bytes())?;
        s.complete(&tag).context("IMAP login failed")?;
        let caps = s.cmd("CAPABILITY")?;
        s.caps = caps
            .iter()
            .filter(|l| l.untagged_kind() == Some("CAPABILITY"))
            .flat_map(|l| l.toks[2..].iter().map(|t| t.atom().to_ascii_uppercase()))
            .collect();
        Ok(s)
    }

    pub fn logout(mut self) {
        let _ = self.cmd("LOGOUT");
    }

    pub fn list(&mut self) -> Result<Vec<Folder>> {
        let lines = self.cmd("LIST \"\" \"*\"").context("IMAP LIST")?;
        let mut folders: Vec<Folder> = lines.iter().filter_map(parse_list).collect();
        folders.sort_by_key(|f| (!f.name.eq_ignore_ascii_case("INBOX"), f.name.to_lowercase()));
        folders.dedup_by(|a, b| a.name == b.name);
        Ok(folders)
    }

    pub fn create(&mut self, folder: &str) -> Result<()> {
        self.cmd(&format!("CREATE {}", astring(&encode_mutf7(folder))))
            .with_context(|| format!("creating folder {folder:?}"))?;
        Ok(())
    }

    /// SELECT a folder read-write; returns its UIDVALIDITY.
    pub fn select(&mut self, folder: &str) -> Result<u32> {
        self.open("SELECT", folder)
    }

    /// EXAMINE a folder read-only (nothing, not even \Recent, changes).
    pub fn examine(&mut self, folder: &str) -> Result<u32> {
        self.open("EXAMINE", folder)
    }

    fn open(&mut self, verb: &str, folder: &str) -> Result<u32> {
        let lines = self
            .cmd(&format!("{verb} {}", astring(&encode_mutf7(folder))))
            .with_context(|| format!("opening {folder}"))?;
        lines
            .iter()
            .find_map(|l| {
                let t = l.text.to_ascii_uppercase();
                let i = t.find("[UIDVALIDITY ")?;
                t[i + 13..].split(']').next()?.trim().parse().ok()
            })
            .context("server did not report UIDVALIDITY")
    }

    /// Every message in the selected folder. With `full`, the whole message
    /// is fetched (for body tests); otherwise just the header.
    pub fn fetch_all(&mut self, full: bool) -> Result<Vec<Fetched>> {
        let what = if full { "BODY.PEEK[]" } else { "BODY.PEEK[HEADER]" };
        self.fetch(&format!("UID FETCH 1:* (UID RFC822.SIZE {what})"))
    }

    pub fn fetch_full(&mut self, uids: &[u32]) -> Result<Vec<Fetched>> {
        let mut out = Vec::new();
        for set in uid_sets(uids) {
            out.extend(self.fetch(&format!("UID FETCH {set} (UID RFC822.SIZE BODY.PEEK[])"))?);
        }
        Ok(out)
    }

    fn fetch(&mut self, cmd: &str) -> Result<Vec<Fetched>> {
        let lines = self.cmd(cmd).context("IMAP FETCH")?;
        let mut out = Vec::new();
        for l in &lines {
            if l.untagged_kind() != Some("FETCH") {
                continue;
            }
            let Some(Tok::List(items)) = l.toks.get(3) else { continue };
            let (mut uid, mut size, mut data) = (None, 0, Vec::new());
            for kv in items.chunks(2) {
                let [k, v] = kv else { break };
                let k = k.atom().to_ascii_uppercase();
                if k == "UID" {
                    uid = v.atom().parse().ok();
                } else if k == "RFC822.SIZE" {
                    size = v.atom().parse().unwrap_or(0);
                } else if k.starts_with("BODY[") {
                    if let Tok::Bytes(b) = v {
                        data = b.clone();
                    }
                }
            }
            if let Some(uid) = uid {
                out.push(Fetched { uid, size, data });
            }
        }
        out.sort_by_key(|f| f.uid);
        Ok(out)
    }

    /// Add flags/keywords such as `\Seen` or `$Label1`.
    pub fn add_flags(&mut self, uids: &[u32], flags: &[String]) -> Result<()> {
        let flags = flags.join(" ");
        for set in uid_sets(uids) {
            self.cmd(&format!("UID STORE {set} +FLAGS.SILENT ({flags})"))
                .context("setting flags")?;
        }
        Ok(())
    }

    pub fn copy(&mut self, uids: &[u32], folder: &str) -> Result<()> {
        let f = astring(&encode_mutf7(folder));
        for set in uid_sets(uids) {
            self.cmd(&format!("UID COPY {set} {f}"))
                .with_context(|| format!("copying to {folder}"))?;
        }
        Ok(())
    }

    /// MOVE (RFC 6851), or COPY + \Deleted + UID EXPUNGE where unsupported.
    pub fn move_to(&mut self, uids: &[u32], folder: &str) -> Result<()> {
        let has = |c: &str| self.caps.iter().any(|x| x == c);
        if has("MOVE") || has("IMAP4REV2") {
            let f = astring(&encode_mutf7(folder));
            for set in uid_sets(uids) {
                self.cmd(&format!("UID MOVE {set} {f}"))
                    .with_context(|| format!("moving to {folder}"))?;
            }
            return Ok(());
        }
        if !has("UIDPLUS") {
            bail!("server supports neither MOVE nor UIDPLUS, so messages can't be moved safely");
        }
        self.copy(uids, folder)?;
        for set in uid_sets(uids) {
            self.cmd(&format!("UID STORE {set} +FLAGS.SILENT (\\Deleted)"))?;
            self.cmd(&format!("UID EXPUNGE {set}"))?;
        }
        Ok(())
    }

    // ---- wire format -------------------------------------------------------

    fn next_tag(&mut self) -> String {
        self.tag += 1;
        format!("v{}", self.tag)
    }

    fn write(&mut self, b: &[u8]) -> Result<()> {
        let w = self.r.get_mut();
        w.write_all(b)?;
        w.flush()?;
        Ok(())
    }

    /// Send a command; return its untagged responses, Err unless tagged OK.
    fn cmd(&mut self, cmd: &str) -> Result<Vec<Line>> {
        let tag = self.next_tag();
        self.write(format!("{tag} {cmd}\r\n").as_bytes())?;
        self.complete(&tag)
    }

    fn complete(&mut self, tag: &str) -> Result<Vec<Line>> {
        let mut lines = Vec::new();
        loop {
            let l = self.read()?;
            if l.toks.first().map(Tok::atom) == Some(tag) {
                if l.is_status(tag, "OK") {
                    return Ok(lines);
                }
                bail!("server said {}", l.text);
            }
            if l.is_status("*", "BYE") {
                bail!("server said {}", l.text);
            }
            lines.push(l);
        }
    }

    fn read(&mut self) -> Result<Line> {
        Reader { r: &mut self.r }.line()
    }
}

enum Tok {
    Atom(String),
    Bytes(Vec<u8>),
    List(Vec<Tok>),
}

impl Tok {
    fn atom(&self) -> &str {
        match self {
            Tok::Atom(a) => a,
            _ => "",
        }
    }
    fn text(&self) -> String {
        match self {
            Tok::Atom(a) => a.clone(),
            Tok::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            Tok::List(_) => String::new(),
        }
    }
}

struct Line {
    toks: Vec<Tok>,
    /// Free text after a status keyword (OK/NO/BAD/BYE/PREAUTH) or `+`.
    text: String,
}

impl Line {
    fn is_status(&self, tag: &str, kw: &str) -> bool {
        self.toks.first().map(Tok::atom) == Some(tag)
            && self.toks.get(1).is_some_and(|t| t.atom().eq_ignore_ascii_case(kw))
    }
    /// `* CAPABILITY …` → CAPABILITY; `* 3 FETCH …` → FETCH.
    fn untagged_kind(&self) -> Option<&str> {
        if self.toks.first()?.atom() != "*" {
            return None;
        }
        let k = self.toks.get(1)?.atom();
        if !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) {
            self.toks.get(2).map(Tok::atom)
        } else {
            Some(k)
        }
    }
}

/// Reads one response line, with literals read inline and nested lists.
struct Reader<'a> {
    r: &'a mut BufReader<Box<dyn Stream>>,
}

impl Reader<'_> {
    fn peek(&mut self) -> Result<u8> {
        let b = self.r.fill_buf()?;
        b.first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("server closed the connection"))
    }

    fn bump(&mut self) -> Result<u8> {
        let b = self.peek()?;
        self.r.consume(1);
        Ok(b)
    }

    fn rest_of_line(&mut self) -> Result<String> {
        let mut v = Vec::new();
        self.r.read_until(b'\n', &mut v)?;
        Ok(String::from_utf8_lossy(&v).trim().to_string())
    }

    fn line(&mut self) -> Result<Line> {
        let mut stack: Vec<Vec<Tok>> = vec![Vec::new()];
        loop {
            // Status responses end in free text that may contain anything.
            if stack.len() == 1 && at_status_text(&stack[0]) {
                let text = self.rest_of_line()?;
                return Ok(Line {
                    toks: stack.pop().unwrap(),
                    text,
                });
            }
            match self.peek()? {
                b' ' => {
                    self.bump()?;
                }
                b'\r' | b'\n' => {
                    self.rest_of_line()?;
                    if stack.len() != 1 {
                        bail!("IMAP protocol error: unbalanced parentheses");
                    }
                    return Ok(Line {
                        toks: stack.pop().unwrap(),
                        text: String::new(),
                    });
                }
                b'(' => {
                    self.bump()?;
                    stack.push(Vec::new());
                }
                b')' => {
                    self.bump()?;
                    if stack.len() < 2 {
                        bail!("IMAP protocol error: unexpected )");
                    }
                    let l = stack.pop().unwrap();
                    stack.last_mut().unwrap().push(Tok::List(l));
                }
                b'"' => {
                    self.bump()?;
                    let mut v = Vec::new();
                    loop {
                        match self.bump()? {
                            b'"' => break,
                            b'\\' => v.push(self.bump()?),
                            b => v.push(b),
                        }
                    }
                    stack.last_mut().unwrap().push(Tok::Bytes(v));
                }
                b'{' => {
                    self.bump()?;
                    let mut n = String::new();
                    loop {
                        match self.bump()? {
                            b'}' => break,
                            b'+' => {}
                            b => n.push(b as char),
                        }
                    }
                    let n: usize = n.parse().context("IMAP literal length")?;
                    if self.bump()? == b'\r' {
                        self.bump()?;
                    }
                    let mut v = vec![0; n];
                    self.r.read_exact(&mut v)?;
                    stack.last_mut().unwrap().push(Tok::Bytes(v));
                }
                _ => {
                    // Atoms like `BODY[HEADER.FIELDS (A B)]` keep their [] part.
                    let mut a = String::new();
                    let mut depth = 0i32;
                    loop {
                        let b = self.peek()?;
                        match b {
                            b'[' => depth += 1,
                            b']' => depth -= 1,
                            b' ' | b'(' | b')' | b'\r' | b'\n' if depth <= 0 => break,
                            _ => {}
                        }
                        a.push(self.bump()? as char);
                    }
                    stack.last_mut().unwrap().push(Tok::Atom(a));
                }
            }
        }
    }
}

fn at_status_text(toks: &[Tok]) -> bool {
    const KW: [&str; 5] = ["OK", "NO", "BAD", "BYE", "PREAUTH"];
    match toks {
        [Tok::Atom(p)] => p == "+",
        [Tok::Atom(_), Tok::Atom(k)] => KW.iter().any(|w| k.eq_ignore_ascii_case(w)),
        _ => false,
    }
}

/// `* LIST (\HasNoChildren) "/" "Lists/Debian"` → folder `Lists/Debian`;
/// None for other lines and for `\Noselect` / `\NonExistent` folders.
fn parse_list(l: &Line) -> Option<Folder> {
    if l.untagged_kind()? != "LIST" {
        return None;
    }
    let Tok::List(flags) = l.toks.get(2)? else {
        return None;
    };
    let has = |f: &str| flags.iter().any(|t| t.atom().eq_ignore_ascii_case(f));
    if has("\\Noselect") || has("\\NonExistent") {
        return None;
    }
    let name = l.toks.get(4)?.text();
    Some(Folder {
        name: decode_mutf7(&name).unwrap_or(name),
        trash: has("\\Trash"),
    })
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

/// UTF-8 → IMAP modified UTF-7, for folder names in commands.
fn encode_mutf7(s: &str) -> String {
    fn flush(pending: &mut Vec<u16>, out: &mut String) {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        out.push('&');
        out.push_str(&b64.replace('/', ","));
        out.push('-');
        pending.clear();
    }
    let mut out = String::new();
    let mut pending: Vec<u16> = Vec::new();
    for ch in s.chars() {
        if (' '..='~').contains(&ch) {
            flush(&mut pending, &mut out);
            out.push(ch);
            if ch == '&' {
                out.push('-');
            }
        } else {
            let mut buf = [0u16; 2];
            pending.extend_from_slice(ch.encode_utf16(&mut buf));
        }
    }
    flush(&mut pending, &mut out);
    out
}

/// A quoted string (folder names are ASCII after modified UTF-7).
fn astring(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// UIDs as compact sequence sets, at most 200 ranges per command.
fn uid_sets(uids: &[u32]) -> Vec<String> {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut ranges: Vec<String> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            i += 1;
            end = sorted[i];
        }
        ranges.push(if start == end {
            start.to_string()
        } else {
            format!("{start}:{end}")
        });
        i += 1;
    }
    ranges.chunks(200).map(|c| c.join(",")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn parse(s: &[u8]) -> Line {
        let stream: Box<dyn Stream> = Box::new(Cursor::new(s.to_vec()));
        Reader {
            r: &mut BufReader::new(stream),
        }
        .line()
        .unwrap()
    }

    fn folder(s: &[u8]) -> Option<String> {
        parse_list(&parse(s)).map(|f| f.name)
    }

    #[test]
    fn list_lines() {
        assert_eq!(
            folder(b"* LIST (\\HasNoChildren) \"/\" \"Lists/Debian\"\r\n").as_deref(),
            Some("Lists/Debian")
        );
        assert_eq!(folder(b"* LIST () \".\" INBOX\r\n").as_deref(), Some("INBOX"));
        assert_eq!(folder(b"* LIST (\\Noselect \\HasChildren) \"/\" \"Lists\"\r\n"), None);
        assert_eq!(
            folder(b"* LIST () NIL \"Say \\\"hi\\\"\"\r\n").as_deref(),
            Some("Say \"hi\"")
        );
        assert_eq!(
            folder(b"* LIST () \"/\" {11}\r\nSent Items!\r\n").as_deref(),
            Some("Sent Items!")
        );
        assert_eq!(folder(b"* OK still (here\r\n"), None);
        let t = parse_list(&parse(b"* LIST (\\HasNoChildren \\Trash) \"/\" \"Deleted Items\"\r\n"));
        assert!(t.unwrap().trash);
    }

    #[test]
    fn fetch_line() {
        let l = parse(b"* 12 FETCH (UID 345 RFC822.SIZE 99 BODY[HEADER] {9}\r\nSubject:\n)\r\n");
        assert_eq!(l.untagged_kind(), Some("FETCH"));
        let Tok::List(items) = &l.toks[3] else { panic!() };
        assert_eq!(items[1].atom(), "345");
        assert_eq!(items[4].atom(), "BODY[HEADER]");
        assert!(matches!(&items[5], Tok::Bytes(b) if b == b"Subject:\n"));
    }

    #[test]
    fn status_text() {
        let l = parse(b"v3 OK [READ-WRITE] it's (done\r\n");
        assert!(l.is_status("v3", "OK"));
        assert_eq!(l.text, "[READ-WRITE] it's (done");
        let c = parse(b"+ \r\n");
        assert_eq!(c.toks[0].atom(), "+");
    }

    #[test]
    fn modified_utf7() {
        assert_eq!(decode_mutf7("INBOX").as_deref(), Some("INBOX"));
        assert_eq!(decode_mutf7("&AOk-t&AOk-").as_deref(), Some("été"));
        assert_eq!(decode_mutf7("Tom &- Jerry").as_deref(), Some("Tom & Jerry"));
        assert_eq!(decode_mutf7("&ZeVnLIqe-").as_deref(), Some("日本語"));
        for s in ["été", "Tom & Jerry", "日本語/Ünter", "Alma Linux"] {
            assert_eq!(decode_mutf7(&encode_mutf7(s)).as_deref(), Some(s));
        }
        assert_eq!(encode_mutf7("été"), "&AOk-t&AOk-");
    }

    #[test]
    fn sets() {
        assert_eq!(uid_sets(&[5, 1, 2, 3, 9, 10]), vec!["1:3,5,9:10"]);
        assert!(uid_sets(&[]).is_empty());
    }
}
