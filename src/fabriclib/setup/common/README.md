# fabriclib/setup/common

Helpers shared by setup steps and the consent plans.

| File | What |
|---|---|
| `missing_packages.py` | Which Debian packages are not installed |
| `apt_install.py` | Install packages from the host's own apt sources (noninteractive) |
| `render_member_files.py` | The host's krb5.conf and sssd.conf as a member of its own domain: the fabric admins only, sudo from the site's rules |
| `export_dc_keytab.py` | The keys of the DC's own account and its host/ names (never the whole domain's), read from the samba container |
| `docker_ready.py` | Whether Docker, compose v2 and buildx answer |
| `service_account_name.py` | A service's host account name (`fabric-dns`, …): `service_users.<key>.name` or fabric's default |
| `previous_accounts.py` | The service accounts of releases before 2026-10 (names, ids), which setup moves away from |
