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
2. You never manage Sieve scripts. The app owns exactly one server script,
   `vera-colander`, and keeps it active. The sidebar shows **groups** of rules
   (e.g. Cooking, Kernel Updates, AlmaLinux): collapse them, reorder them with
   ⬆/⬇, and switch a whole group on or off with its checkbox. Rules inside a
   group keep their order, *Enabled* and *Stop here*.
3. Build rules: pick a field (From, From domain, Subject, List-Id, Size, any
   header…), an operator, and values (separate alternatives with `|`). Add
   actions: move to folder, set flags (mark read), forward, discard, reject,
   auto-reply. The generated Sieve for the selected rule updates live. The
   📁 button next to a folder lists your mailboxes (fetched over IMAP on port
   993 with the same login); you can also type a name. *➕ Raw Sieve* adds a
   block of hand-written Sieve that is inserted verbatim at its position; its
   `require` lines are moved into the script's single `require`.
4. **Save** (Ctrl/Cmd+S) compiles every enabled group, top to bottom, into
   one script with one merged `require`, then runs CHECKSCRIPT, PUTSCRIPT
   `vera-colander` and SETACTIVE `vera-colander`. **Check** only validates.
   *Generated Sieve* shows the whole script (read-only).
5. Filters only run on new mail. To apply a rule to what is already in the
   Inbox, tick *Apply to the Inbox when I save* or click *Run on Inbox now*:
   the app previews the matching messages and what will happen to each, then
   applies it on confirmation (IMAP 993 for move/copy/flags, SMTP submission
   on 465 for forwards; delete moves to Trash; auto-reply, reject and raw
   Sieve blocks are not applied to old mail).

**First connect.** If the server has other scripts, the app offers to import
them: scripts made by this app come in with their groups and rules, anything
else as a group holding one raw Sieve block. Only the active script was
running, so the others arrive as disabled groups. After the import is saved,
the app offers to delete the old scripts. *More… → Import server scripts…*
repeats this later.

**Every connect.** If another program made a different script active, a
banner says so (“Another app activated … Your rules aren't running.”) with a
**Take over** button that re-activates `vera-colander`.

**Advanced** (bottom of the sidebar) lists the raw scripts on the server and
opens them read-only, for debugging.

The groups and rules are stored inside the uploaded script as a `#@` comment
block, so any machine (GUI or CLI) can reopen them. Connection settings
persist between runs; the password only lives in the keychain.

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

sievectl group add Work                    # groups run top to bottom
sievectl group ls | rm NAME | enable NAME | disable NAME | move NAME 1

sievectl rule add -g Work -n "GitHub" \
  --if "from.domain is github.com" \
  --then "fileinto GitHub" --stop

sievectl rule add -g Work -n "Invoices" --create \
  --if "from.domain is acme.com" --if "subject contains invoice|statement" \
  --then "fileinto Finance/Acme" --then read --then stop

sievectl rule add -n "No-reply junk" --any \
  --if "from.localpart is noreply|no-reply" --if "x-spam-flag is YES" \
  --then discard

sievectl rule list [-g GROUP] | show NAME | disable NAME | enable NAME | move NAME 1 | rm NAME
sievectl pull                    # get the groups back from "vera-colander" into rules.toml
sievectl compile                 # print the generated Sieve
sievectl deploy --activate       # CHECKSCRIPT, PUTSCRIPT "vera-colander" (skipped if unchanged), SETACTIVE
sievectl deploy --dry-run        # validate on the server only
```

**Condition:** `FIELD [not] OP [VALUE|VALUE...]`

- Fields: `from to cc bcc sender reply-to to-or-cc subject body size envelope-from envelope-to`,
  or any header name (`list-id`, `x-spam-flag`, ...). Address fields take `.domain` / `.localpart`.
- Ops: `is contains matches regex exists over under` (`size over 10M`).

**Actions:** `fileinto F`, `copy F` (fileinto :copy), `redirect ADDR`, `forward ADDR`
(redirect :copy), `keep`, `discard`, `reject TEXT`, `flag \\Flagged`, `read`,
`vacation TEXT`, `stop`. `--create` makes missing folders.

`rule add` without `-g` uses a group called "Rules" (created if needed);
other `rule` commands find the rule in any group, and take `-g` when two
groups have a rule with the same name. Rules files from before groups load
as one "Rules" group. A rule with `raw = """…"""` is hand-written Sieve.

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

Unit tests (`cargo test`) cover the compiler (several groups, `require`
merging and de-duplication, disabled groups, raw blocks with hoisted
`require`, metadata round-trip, legacy files), IMAP parsing, and Inbox rule
evaluation. `one_script_migration_end_to_end` imports two existing scripts,
saves the single `vera-colander` script, checks it is active and reopens
identically, then deletes the old scripts. It runs against an in-process fake
server, or against a real one with
`SIEVE_E2E=host:port:user:pass cargo test one_script_migration` (plain TCP).

End-to-end runs against Dovecot 2.4 / Pigeonhole: CLI (auth failure,
CHECKSCRIPT errors, grouped deploy with raw blocks, unchanged detection,
pull round-trip, edit, rename, delete-active refusal). Earlier versions were
also run against Dovecot 2.3 with the GUI.
