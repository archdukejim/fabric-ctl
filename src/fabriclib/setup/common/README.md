# fabriclib/setup/common

Helpers shared by setup steps and the consent plans.

| File | What |
|---|---|
| `missing_packages.py` | Which Debian packages are not installed |
| `apt_install.py` | Install packages from the host's own apt sources (noninteractive) |
| `render_member_files.py` | The host's krb5.conf and sssd.conf as a member of its own domain: no domain account signs in and no domain sudo rule applies (the top tier's host) |
| `sssd_sockets.py` | sssd's socket units (`sssd-*.socket`): read, masked for the host's own join and put back by its undo; the Linux join's script follows its glob and commands (1.6.7.8, 2.1.6.95) |
| `host_identity.py` | Which domain account the host signs in with: its own `<HOSTNAME>$` (2.1.6.48), or its DC's where it cannot have its own; a DC with the host's name refused (2.1.6.51) |
| `find_computer.py` | Whether the domain has a computer account of a name, where, and its groups (read inside the DC) |
| `sshd_check.py` | Whether sshd accepts its configuration as it is on disk (`sshd -t`) |
| `apply_host_managed.py` | fabric's management of the fabric host itself, applied or removed: Kerberos for SSH, a domain password refused over SSH, the domain's names from fabric's DNS; local accounts untouched, sshd's configuration checked (1.6.11.11) |
| `sync_host_managed.py` | The host's management kept in step with its account's membership of `fabric-managed` (`fabricctl domain host-managed`, the timer) |
| `renew_days.py` | After how many days the host's machine password is renewed (`host_machine_password_renew_days`, 0 = never) |
| `export_keytab.py` | The keys of the host's domain account and its host/ names (never the whole domain's), read from the samba container |
| `docker_ready.py` | Whether Docker, compose v2 and buildx answer |
| `service_account_name.py` | A service's host account name (`fabric-dns`, …): `service_users.<key>.name` or fabric's default |
| `valid_setting.py` | The checks of the asked settings (domain, host name, network, organisation, first admin) and their labels |
| `ask_setting.py` | Ask one setting until its answer is valid (guided mode and the menu) |
| `network_problem.py` | What is wrong with the host's address, subnet and gateway taken together |
| `ca_exists.py` | Whether this install's CA exists (its lifetime is then fixed) |
| `first_admin_needed.py` | Whether setup creates the first admin and so needs their password |
| `first_admin_refused.py` | Why an answer for the first Directory Administrator is refused: their user name (fabric's names, fabric-admin), first and last names, e-mail (optional) (2.1.6.69, 2.1.6.93) |
| `retired_settings.py` | The one table of the settings a 0.7.x file holds that 0.8.0 no longer takes, with why (2.1.1.60, manual 3.3.5.3), and 0.7.x's own groups |
| `read_vars_file.py` | Reads the vars file given to setup and refuses one that is damaged or not fabric's, nothing changed |
| `ask_admin_fact.py` | One of the first Directory Administrator's facts asked until it is taken, saying why not |
| `plan_items.py` | The plan's hardened defaults (the firewall, Docker's hardening, membership, Keycloak, the web console) |
| `dotted_keys.py` | Read and write a dotted settings key (`security.firewall`) |
| `parse_log_target.py` | Where log forwarding sends the logs, from one line: a syslog server or an Elasticsearch URL |
