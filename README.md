# sievectl

Cross-platform (Linux, macOS, Windows) ManageSieve client (RFC 5804) with a
rule builder: describe mail filters in a TOML file, and `sievectl` compiles
them to Sieve (RFC 5228), validates them on the server, and uploads them.

Single static binary, pure-Rust TLS (rustls + ring); no OpenSSL needed.

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

Password order: `$SIEVE_PASSWORD` → `password_command` → prompt.
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

Unit tests plus an end-to-end run against Dovecot 2.3 / Pigeonhole (STARTTLS,
auth failure, CHECKSCRIPT errors, deploy, edit, rename, delete-active refusal).
