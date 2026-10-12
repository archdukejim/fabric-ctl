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
| `valid_setting.py` | The checks of the asked settings (domain, host name, network, organisation, first admin) and their labels |
| `ask_setting.py` | Ask one setting until its answer is valid (guided mode and the menu) |
| `network_problem.py` | What is wrong with the host's address, subnet and gateway taken together |
| `ca_exists.py` | Whether this install's CA exists (its lifetime is then fixed) |
| `first_admin_needed.py` | Whether setup creates the first admin and so needs their password |
| `plan_items.py` | The plan's hardened defaults (the firewall, Docker's hardening, membership, Keycloak, the web console) |
| `dotted_keys.py` | Read and write a dotted settings key (`security.firewall`) |
| `previous_accounts.py` | The service accounts of releases before 2026-10 (names, ids), which setup moves away from |
