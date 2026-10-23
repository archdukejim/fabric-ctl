# fabriclib/setup

`fabricctl setup` — install or re-converge fabric on this host. Every step is idempotent and can run alone:
`sudo fabricctl setup --step <name>`; `--list` shows them in order.

| File | What |
|---|---|
| `run_setup.py` | CLI for `fabricctl setup` / `doctor`: options, input, plan; hands a full run's steps to `fabric-setup.service` (detach/) |
| `steps.py` | The ordered step list |
| `run_steps.py` | Runs the selected steps in order, then *fabric is ready*; keeps a full run's record after each step (2.1.2.26) |
| `detach/` | Setup's work as `fabric-setup.service`: hand-off, following, re-attaching, resuming (1.3.2.3) |
| `context.py` | `SetupContext`: install paths, rendered vars, secrets, options, services to restart |
| `errors.py` | `SetupError` — a step cannot continue; message says why and what to do |
| `choose_mode.py` | A new install's start: [G]uided, [A]dvanced (the menu of every setting) or [Q]uit (1.2.9.11.1) |
| `collect_vars.py` | Where settings come from: existing install, `--file` (or a checkout's `custom-vars.yaml` on a fresh install) overrides, prompts for anything missing (guided mode) |
| `drop_retired_settings.py` | A settings file of an older fabric taken as it is (2.1.1.60): the keys this release no longer takes, listed with why and ignored (the table: `common/retired_settings.py`) |
| `apply_plan_defaults.py` | The plan's hardened defaults recorded as values, so what is shown is what renders |
| `finish_vars.py` | The last of collecting the settings: a fresh install's log-on rights, TSIG secrets moved, `fabric.yaml` saved |
| `upgrade_vars.py` | Existing install's vars before re-render: the release's images, unless pinned (what it did for installs before 0.8.0 is retired, 2.1.1.61) |
| `detect_network.py` | Guess hostname, host IP, gateway, LAN CIDR and interface from the default route |
| `choose_plan.py` | The plan: what setup will do, the memory split, every host change; [P]roceed (the one yes), [M]enu, [Q]uit |
| `advanced/` | The menu of every setting (1.2.9.11.3): its items and their questions |
| `permanent_mark.py` | The yellow "⚠ Permanent" after a question whose setting is in the vars editor's `IMMUTABLE_KEYS` (2.1.2.20) |
| `name_dc.py` | The domain controller's name, fabric's alone (2.1.6.65): `dc-0001` for a new domain, the upstream's for a joining site, an installed DC's kept; never asked |
| `ask_ad_domain.py` | The directory's AD domain (permanent; a sibling suggested), asked when missing; its password policy starts from the default (2.1.6.35) |
| `ask_first_admin.py` | The first admin's password, chosen in setup: typed twice and checked against the policy, or from `--admin-password-file` (2.1.6.33) |
| `preflight.py` | Refuse a host without amd64/arm64, root, enough RAM or the cgroup memory controller; warn about untested OS and conflicting listeners |
| `condition_host.py` | Host packages and Docker Engine (compose v2, buildx) from the Ubuntu archive; no apt source added |
| `harden_docker.py` | Hardened `/etc/docker/daemon.json` (merged, not replaced), after the `runtime` consent |
| `deploy_config.py` | Render + deploy all configuration without starting anything; install `fabricctl` |
| `set_ram_capacity.py` | The memory fabric sizes itself for: all of the host's measured memory unless set (4 GB at least; 2.1.2.3, 2.1.2.16) |
| `create_accounts.py` | `fabric-*` service users and groups (uid band 600–649); moves an older install off its previous accounts |
| `configure_network.py` | Docker network `fabric_net`; optional host resolver drop-in |
| `configure_firewall.py` | UFW default-deny (SSH from the LAN) + LAN-only Docker-published ports; lockout guard |
| `join_federation.py` | Step `join` (only with `--join`): join the upstream before anything is rendered — site CA signed by the organisation's root, organisation settings |
| `read_join_invitation.py` | The `--join` invitation from a hidden prompt, a file or stdin — never from the command line |
| `init_pki.py` | Step-CA init (own root or bring-your-own), `ca.json`, CA certs published and trusted |
| `start_bootstrap.py` | Start bind9 + step-ca; validate every zone |
| `mint_service_certs.py` | Issue/renew service certificates (only what is missing, expiring or wrong); web UI and FreeRADIUS CA bundles |
| `mint_extra_certs.py` | `extra_certs` entries, when missing or due (part of the `certs` step) |
| `join_host_domain.py` | Step `member`: this host a member of its own domain with its own computer account in OU=fabric-hosts (2.1.6.48; keytab, krb5.conf, sssd.conf, NSS, PAM); no domain account signs in (2.1.6.75) |
| `start_services.py` | Retire renamed units; start the stack in order; converge the domain; configure Keycloak; fabric-agent + web UI; activate `fabric.target` |
| `service_order.py` | fabric's container services in dependency order: setup starts them in it, an apply's rollout restarts them in it (2.1.14.15) |
| `start_unit.py` | Enable, start or restart one unit and wait until its container is healthy |
| `setup_openbao.py` | `vault` step: vault key and unlock, start OpenBao, init once (recovery keys to `~/fabric-admin`, root token used once and revoked), converge its configuration, move fabric's secrets file into OpenBao |
| `create_admin.py` | First web UI admin: a person in the domain, in the admin group, forced password change, client `.p12`, root CA and README in `~/fabric-admin` |
| `print_first_steps.py` | Setup's last words: the root certificate from the landing page first, then sign in (2.1.1.41) |
| `verify_install.py` | End-to-end checks (DNS, HTTPS chains, web UI gates, time, services) |
| `wait_ready.py` | The `ready` step: waits until the landing page, sign-in, the console and Keycloak's database answer together before setup says it is ready (2.1.2.25) |
| `uninstall.py` | Remove fabric (only fabric's own objects) |
| `run_restore_command.py` | `fabricctl restore <export>`: put an export back and run setup on it (refused while installed) |
| `run_uninstall_command.py` | `fabricctl uninstall`: asks about an export and the package first, then exports, uninstalls, optionally `apt purge` |
| `export_install.py` | Export all of fabric's data (secrets from OpenBao, then every folder copied cold, vault key, README) to a folder you choose |
| `check_export_dir.py` | Refuse an export folder the uninstall would delete, or one that is not new/empty |
| `backup_install.py` | `reinstall`: keep config, secrets (exported from OpenBao), CA, certificates and OpenBao (data + key) in `/root` (owners preserved; not the directory or Keycloak data) |
| `restore_install.py` | Put a reinstall backup or a full export back under the install root (owners preserved) |
| `stage_source.py` | Reinstall from the installed copy: stage the code in `/var/tmp` so uninstall cannot delete what setup runs from |
| `renew_service_certs.py` | `fabricctl certs [--force / --scheduled]`: renewal (the daily timer's too); each changed service reloaded or restarted (pick_up_cert); the run recorded for status and doctor |
| `common/` | Helpers shared with the consent plans |
| `doctor_report.py` | Doctor's checks as data, for the web console's Run doctor |
| `ensure_db_rotation.py` | Step `dbrotation`: Postgres's own admin and Keycloak's own role, OpenBao's database engine and static role for Keycloak's password (2.1.7.4) |
| `setup_local_admin.py` | Step `localadmin`: this host's local-admin made and its password set by OpenBao, then the hourly check once (2.1.7.16) |
