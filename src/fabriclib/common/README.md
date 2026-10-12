# fabriclib/common

| File | What |
|---|---|
| `ask.py` | `ask` / `ask_secret`: every question fabric asks a person, each with a stable ID (`<area>.<name>`, manual 1.1.5.6) |
| `paths.py` | Well-known paths derived from the install location (`FABRIC_DIR`, `VARS_FILE`, `AUDIT_FILE`, …) |
| `read_images_lock.py` | The validated, digest-pinned images (`config/images.lock.yaml`) with their refs |
| `read_packages_lock.py` | The pinned packages built into fabric's own images (`packages:` in `images.lock.yaml`: Kea from ISC's repository, key fingerprint, version) |
| `jinja_env.py` | The Jinja environment deploy and the tests render with (Ansible-style filters, `images_lock` / `packages_lock` globals) |
| `errors.py` | `ValidationError` — input rejected; message is safe to show to users |
| `load_vars.py` | Read `vars.yaml` (empty dict if missing) |
| `save_vars.py` | Write `vars.yaml`, empty strings stored as null |
| `vars_lock.py` | Exclusive lock around read-modify-write of `vars.yaml` |
| `write_audit.py` | Append one line to the audit log with the acting user and source |
| `read_audit.py` | Last N audit lines, newest first |
| `run.py` | Run a command as an argument list (never a shell); raise `CommandError` with stderr on failure |
| `console.py` | `heading` / `info` / `ok` / `warn` / `err` output (colour only on a terminal) |
| `wait_healthy.py` | Wait for a container's Docker healthcheck |
| `dns_query.py` | A-record lookup against one DNS server (stdlib; no `dig` needed) |
| `dns_wire.py` | A DNS query in wire format and the A records of its reply (shared by `dns_query` and `doh_query`) |
| `doh_query.py` | A-record lookup over DNS-over-HTTPS (`POST /dns-query` with curl, verified against fabric's root) |
| `dot_query.py` | A-record lookup over DNS-over-TLS (port 853, verified against fabric's root for the DNS name) |
| `sudo_owner.py` | Login, home, uid and gid of the account that ran `sudo` (files handed to the admin) |
| `set_tsig_secrets.py` | Set or remove TSIG secrets in `fabric-secrets.yml` (kept `0600`) |
| `write_file_if_changed.py` | Write a file atomically with its mode and owner, only if its content changed (Kea, FreeRADIUS configs) |
| `one_time_password.py` | A random password for a person that the domain's password policy always accepts (every character kind) |
| `keep_original.py` | Keep a host file (or its symlink target, or its absence) once, before fabric first changes it, in `config/host-originals/` |
| `restore_original.py` | Put a kept host file back (or remove one fabric added) |
| `copy_if_changed.py` | Install one file (mode, owner) when its content differs |
| `copy_tree_with_perms.py` | Copy a tree setting owner and mode; say whether anything changed |
| `ensure_dir.py` | A directory with the given mode and owner |
| `service_user.py` | A service's uid/gid from `service_users` |
| `read_published_lock.py` | fabric's own published images as the lock pins them (`published:` in `images.lock.yaml`), signer and issuer |
| `lock_dir.py` | Where `images.lock.yaml` is for a jinja folder (the host's fabric/, or the checkout's config/) |
