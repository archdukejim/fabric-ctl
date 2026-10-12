# tests

Suites prove behaviour against real containers ([3.1.2](../docs/volume_3_installation/3.1.2-automated-tests.md#312-automated-tests)). Run them with
`sudo tests/run-all.sh [suite ...]` (all but `sandbox` by default); each suite
writes its log to `$FABRIC_TEST_OUT` (default `/tmp/fabric-tests`). The `docs`
suite needs no Docker or root and also runs alone: `python3 tests/docs/run.py`.

| Suite | Where | What it proves |
|---|---|---|
| `docs` | [docs/](docs/) | Every function documented (Purpose/Inputs/Returns/Fails/Feeds), the function reference (manual 1.17) current, docs and code agree, every file reviewed |
| `lint` | [lint/](lint/) | ruff (Python, `pyproject.toml`) and shellcheck (shell) from their pinned images: no findings in `src/`, `scripts/`, `tests/` (decision 2.1.1.15); every product file parses on Python 3.10 (2.1.1.43) |
| `deploy` | [deploy/](deploy/) | An apply's measured rollout: one service at a time in dependency order, health-gated, stopped at the first failure (2.1.14.15), systemd stood in for |
| `consent` | [consent/](consent/) | Asking before fabric changes the host: answers, questions, the subset rule, declined groups, the `fabric-*` accounts and their move, no containers |
| `render` | `render.py` | Every template renders from `vars.yaml.j2`; security properties of the rendered configs; every module imports |
| `nginx` | `nginx_check.sh` | The rendered nginx configuration passes `nginx -t` in the pinned image |
| `zone` | `zone_test.py` | `deploy.py`'s zone deployment with `rndc` stubbed: unchanged records ignored, changed zones found, fresh mtime, BIND's late write detected and the swap repeated, stale journal removed |
| `zones` | [zones/](zones/) | Zones added and removed in seconds (1.4.1.3) with real BIND and resolver containers: through fabric-agent's routes and the menu, every refused name, the rollback when a reload fails, removal refused while a TSIG key names the zone |
| `webui` | [webui/](webui/) | The web UI container against a mock Keycloak and the real fabric-agent; the dev preview |
| `pki` | [pki/](pki/) | Manual PKI against a real Step-CA |
| `resolver` | [resolver/](resolver/) | The DNS filter's BIND resolver (real containers, run as its compose file says): the list converter, refused settings and clients, fabric's zone never filtered, lists and the owner's rules, logs, reloads, the list job; the query log and statistics in Postgres |
| `ntp` | [ntp/](ntp/) | Time: chrony from fabric's generated config (real containers): serving the LAN and refusing others, a site syncing from its upstream site, the settings and what they refuse |
| `federation` | [federation/](federation/) | Invitations, the federation endpoint, a site joining an upstream (real Step-CA) and directory replication between two real 389-DS (M5) |
| `openbao` | [openbao/](openbao/) | OpenBao: unlock methods (key file, USB, security key, KMIP), rotation, fabric's secrets, policies, break glass |
| `fluentbit` | [fluentbit/](fluentbit/) | Log forwarding to TLS syslog and Elasticsearch receivers |
| `kea` | [kea/](kea/) | Kea DHCP with DDNS into BIND, real DHCP clients |
| `freeradius` | [freeradius/](freeradius/) | 802.1X against a real 389-DS: EAP-TLS, EAP-TTLS, MAB, refusals |
| `samba` | [samba/](samba/) | The Windows domain controller: settings (2.1.6.11, 2.1.6.13), the rendered container, what changes around it; a real DC converged twice, the policy, the GPOs, BIND serving the AD zone through DLZ with signed updates, and the refusals (unsigned updates, another site, service accounts, short or wrong passwords) |
| `keycloak` | [keycloak/](keycloak/) | Keycloak on fabric's directory (Samba AD): bootstrap twice, AD federation, a first sign-in through TOTP and a new password that lands in AD, refusals |
| `hardening` | [hardening/](hardening/) | The core services and OpenBao started from their real compose files work and are hardened |
| `images` | [images/](images/) | fabric's own images build from `packaging/docker-bake.hcl` with a default host's build inputs and pass the smoke test CI runs before publishing (decision 2.1.1.21) |
| `sandbox` | [sandbox/](sandbox/) | A full install from the .deb in a disposable systemd + Docker container (about 30 min; not in the default list) |

Not in `run-all.sh`: [host/](host/) (a subset of the sandbox checks on a real machine over SSH) and [lab/](lab/) (DHCP on the Hyper-V lab's isolated network, manual 1.10.3.8).

| File | What |
|---|---|
| `run-all.sh` | Run suites, report PASS/FAIL per suite |
| `render.py` | The `render` suite |
| `nginx_check.sh` | The `nginx` suite |
| `zone_test.py` | The `zone` suite |
| `image_ref.py` | Print the validated, digest-pinned ref of one image (suites test exactly what fabric runs) |
