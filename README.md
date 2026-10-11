# Vera Colander

Cross-platform (Linux, macOS, Windows) ManageSieve client (RFC 5804) for
building mail filter rules. Two programs share one core:

- **`sievectl-gui`**: desktop app with a point-and-click rule builder.
- **`sievectl`**: command-line client for scripting.

Rules compile to Sieve (RFC 5228), are validated by the server
(CHECKSCRIPT) and uploaded. Pure-Rust TLS (rustls + ring); no OpenSSL.

## GUI

```sh
cargo run --release --bin sievectl-gui
```

1. Enter server, username, password (STARTTLS on 4190 by default). Tick
   *Remember password* to store it in the macOS Keychain, Windows Credential
   Manager or the Linux Secret Service (GNOME Keyring/KWallet). With a saved
   password the app signs in on launch and goes straight to your rules;
   *Log out* disconnects and forgets the saved password.
2. Scripts on the server are listed on the left (★ = active). The active
   script opens automatically. Right-click for activate/rename/delete.
3. Build rules: pick a field (From, From domain, Subject, List-Id, Size, any
   header…), an operator, and values (separate alternatives with `|`). Add
   actions: move to folder, set flags (mark read), forward, discard, reject,
   auto-reply. The generated Sieve for the selected rule updates live.
   The 📁 button next to a folder lists your mailboxes (fetched over IMAP on
   port 993 with the same login); you can also type a name.
4. **Check** asks the server to validate; **Save** (Ctrl/Cmd+S) validates and
   uploads; **Save & activate** makes it the running script.

The rule set is stored inside the uploaded script as a `#@` comment block,
so any machine (GUI or CLI) can reopen it as editable rules. Scripts not made
by this tool open in a raw Sieve editor with server-side validation.
Connection settings persist between runs; the password only lives in the
keychain.

Linux build needs: `libxkbcommon-dev libwayland-dev libgl1-mesa-dev`
(Debian/Ubuntu) or `libxkbcommon-devel wayland-devel mesa-libGL-devel` (Fedora).
CLI only, no GUI deps: `cargo build --release --no-default-features`.

## Build

```sh
cargo build --release            # target/release/sievectl(.exe)
```

Prebuilt binaries for all three OSes come from the GitHub Actions workflow
(push a `v*` tag to publish a release).

## Configure

```sh
sievectl config --init           # creates the per-OS config file and prints its path
```

| OS      | Config path                                           |
|---------|-------------------------------------------------------|
| Linux   | `~/.config/sievectl/config.toml`                      |
| macOS   | `~/Library/Application Support/sievectl/config.toml`  |
| Windows | `%APPDATA%\sievectl\config\config.toml`               |

```toml
[profile.default]
host = "mail.example.com"
user = "you@example.com"
script = "filters"
rules = "/home/you/mail/rules.toml"
# password_command = "pass show mail/sieve"
```

Password order: `$SIEVE_PASSWORD` → `password_command` → system keychain → prompt.
`sievectl login` verifies and stores the password in the keychain (same entry
the GUI uses); `sievectl login --forget` removes it.
Every flag can override the profile: `-H host -u user -p 4190 --tls starttls|implicit|none --ca-file ca.pem`.
Use `-P name` for another `[profile.name]`.

## Write rules

```sh
sievectl init                    # example rules.toml

sievectl rule add -n "GitHub" \
  --if "from.domain is github.com" \
  --then "fileinto GitHub" --stop

sievectl rule add -n "Invoices" --create \
  --if "from.domain is acme.com" --if "subject contains invoice|statement" \
  --then "fileinto Finance/Acme" --then read --then stop

sievectl rule add -n "No-reply junk" --any \
  --if "from.localpart is noreply|no-reply" --if "x-spam-flag is YES" \
  --then discard

sievectl rule list | show NAME | disable NAME | enable NAME | move NAME 1 | rm NAME
sievectl pull filters rules.toml # get rules back from a script on the server
sievectl compile                 # print the generated Sieve
sievectl deploy --activate       # CHECKSCRIPT, then PUTSCRIPT (skipped if unchanged), SETACTIVE
sievectl deploy --dry-run        # validate on the server only
```

**Condition:** `FIELD [not] OP [VALUE|VALUE...]`

- Fields: `from to cc bcc sender reply-to to-or-cc subject body size envelope-from envelope-to`,
  or any header name (`list-id`, `x-spam-flag`, ...). Address fields take `.domain` / `.localpart`.
- Ops: `is contains matches regex exists over under` (`size over 10M`).

**Actions:** `fileinto F`, `copy F` (fileinto :copy), `redirect ADDR`, `forward ADDR`
(redirect :copy), `keep`, `discard`, `reject TEXT`, `flag \\Flagged`, `read`,
`vacation TEXT`, `stop`. `--create` makes missing folders.

The TOML file is the source of truth; `rule` subcommands rewrite it, so
comments in it are not preserved. Hand-edit it freely between runs. The full
field reference is in the header of the file `sievectl init` writes.

## Raw script management

```sh
sievectl caps                    # server capabilities + Sieve extensions
sievectl ls
sievectl get NAME [-o file]
sievectl put NAME file.sieve [--activate]   # validated with CHECKSCRIPT first
sievectl check file.sieve
sievectl edit NAME               # opens $VISUAL/$EDITOR (notepad on Windows), validates before upload
sievectl activate NAME | deactivate | rename OLD NEW | rm NAME
sievectl --debug ls              # protocol trace (password redacted)
```

## Security

- STARTTLS is the default and certificates are verified against the Mozilla
  root set. Self-signed/private CA: `--ca-file ca.pem` (or `ca_file` in config).
- The password is never sent without TLS unless `--allow-plaintext` is given.
- Auth is SASL PLAIN over TLS.

## Tested

Unit tests plus end-to-end runs against Dovecot 2.3 / Pigeonhole: CLI
(STARTTLS, auth failure, CHECKSCRIPT errors, deploy, edit, rename,
delete-active refusal) and GUI (connect, reopen embedded rules, raw edit +
server validation, unsaved-changes prompt, build and save a rule).
