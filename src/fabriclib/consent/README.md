# fabriclib/consent

Asking before fabric changes the host (design [1.2.9](../../../docs/volume_1_description_and_architecture/1.2.9-host-consent.md#1291-status)): what
setup would change outside fabric's own folders, grouped; one yes/no per group before the first step; the
recorded answers; the check every step makes before it changes the host.

| File | What |
|---|---|
| `groups.py` | The groups (packages, runtime, services, accounts, resolver, ports, firewall, own_rules, trust, time, member): title, level (required / recommended / choice), what saying no means |
| `plan_host_changes.py` | Every planned change, by group, for the steps that will run |
| `initial_host_choices.py` | Whether each recommended host change starts on in setup's menu and plan (earlier answers, `--approve` / `--decline`) |
| `planned_vars.py` | The settings setup will render, before anything is deployed (so the questions come first) |
| `plan_packages.py` | apt packages to install, all from the host's own sources (Ubuntu's `docker.io`, no apt source added) |
| `plan_runtime.py` | The `daemon.json` keys hardening changes, and the Docker restart it needs |
| `plan_services.py` | fabric's own systemd units, asked once as a kind |
| `plan_accounts.py` | The `fabric-*` service accounts to create (uid band 600–649) and the move from the previous accounts; refuses ids taken by others |
| `plan_resolver.py` | The resolver change, only with `use_host_dns: false` |
| `plan_firewall.py` | The host firewall, rule by rule |
| `plan_trust.py` | fabric's CA in the host's trust store |
| `plan_time.py` | chrony's configuration, asked once as a kind |
| `plan_member.py` | This host as a member of its domain (1.6.11.8): the packages, the keytab and the files sssd needs; nothing with `host_join_domain: false` |
| `carry_over_splits.py` | An answer given before a group was split, carried to the groups it covered (2.1.2.14) |
| `ask_consent.py` | The questions (interactive, or `--approve` / `--decline`), recorded; stops on a declined required group or an unanswered one |
| `allowed_to_change.py` | Whether changes were approved (subset of what the group's yes covered); never asks |
| `check_consent.py` | A setup step's check: go ahead, skip with a warning (recommended), or stop (required) |
| `load_consent.py` | The recorded answers (`config/consent.yaml`) |
| `save_consent.py` | Write them (0600) |
| `consent_status.py` | The answers for status: approved, declined (with its relaxation), not asked |
| `show_consent_status.py` | Print them for `fabricctl status` |
| `common/` | Helpers shared by the files above |
| `plan_ports.py` | The ports fabric needs opened in ufw (2.1.2.13: the first of the firewall's questions) |
| `plan_own_rules.py` | The host's own ufw rules securing would remove, one by one (2.1.2.13: asked only after securing is allowed) |
