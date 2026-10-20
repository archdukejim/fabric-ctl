# fabriclib

fabric's own Python code, grouped by domain; one operation per file
(see [1.1.5](../../docs/volume_1_description_and_architecture/1.1.5-code-conventions.md#115-code-conventions)). Run with `src` on `sys.path`
and import as `fabriclib.<domain>.<file>`.

| Folder | What |
|---|---|
| [common/](common/) | Shared helpers: paths, vars file, locking, audit log, errors |
| [dns/](dns/) | DNS zones and records in `vars.yaml` (validated), zone sync status |
| [system/](system/) | Version, service status, apply |
| [breakglass/](breakglass/) | `fabric-admin`, the Enterprise Admin and break glass: its generated password, its one file, the reminder, the reset |
| [hostaccounts/](hostaccounts/) | A DC host's local root and administrator accounts: listed, reminded of, approved as break glass |
| [grants/](grants/) | Grants: who may do what, where, by overlapping groups; compiled into groups, GPOs and sudo rules inside the DC (manual 1.6.13) |
| [access/](access/) | fabric-agent's check of who may do what: the tiers, the grants' people and machines rights, a group's two levels; decided inside the DC (manual 1.6.12.17) |
| [domain/](domain/) | Domain management: a person's details and lockout, groups and their managers, the admins' OUs, a computer's folder, type and sites, keytabs, Kerberos, a person's own password (manual 1.6.12.17) |
| [setup/](setup/) | `fabricctl setup`, `doctor`, `uninstall`, `reinstall` — the installer |
| [consent/](consent/) | Asking before fabric changes the host: the change groups, the questions, the recorded answers |
| [undo/](undo/) | Reverting a host change fabric made: `setup --undo GROUP`, and what uninstall does with each |
| [pki/](pki/) | Issue, check and install certificates from Step-CA |
| [security/](security/) | Firewall for Docker-published ports |
| [rbac/](rbac/) | Access control for people: permissions, bundles, what each fabric-agent route needs |
| [dhcp/](dhcp/) | Optional DHCP (Kea 3.0): `dhcp:` checks, config, DDNS zone, reservations, leases, `fabricctl dhcp` |
| [radius/](radius/) | Optional 802.1X (FreeRADIUS): RADIUS clients and their secrets, config, decisions log, `fabricctl radius` |
| [directory/](directory/) | fabric's directory on Samba AD: people, groups and the rest, as the site's agent account (manual 1.6.3) |
| [samba/](samba/) | Optional Windows domain (Samba AD domain controller, manual 1.6.5): its files and, from S1.3, the domain's convergence |
| [logs/](logs/) | Optional log forwarding (Fluent Bit): config, credentials, status |
| [images/](images/) | Container images: status against the validated list, update (health-gated, rollback), prune |
| [keycloak/](keycloak/) | Keycloak over its admin REST API: people, sign-in resets, roles, token checks, the OpenBao OIDC client |
| [vault/](vault/) | OpenBao: init, configure, status, unlock methods (key slots: USB, security key, KMIP), vault key rotation, root token |
| [secrets/](secrets/) | fabric's own secrets: the 0600 file until the vault step, then OpenBao; load, save, import, export |
| [dns_filter/](dns_filter/) | The DNS filter, a BIND resolver: lists converted to response policy zones, its configuration and deploy |
| [menu/](menu/) | The vars editor (`fabricctl --interactive`), `--print` and `--apply` — `lib/interactive.py` is their entry point |
| [deploy/](deploy/) | The deploy engine (apply): secrets, settings, render, install, restart — `lib/deploy.py` is its entry point |
| [ntp/](ntp/) | Time: chrony on the host, serving the network, its settings and checks |
| [settings/](settings/) | The setup wizard's settings (manual 1.8.5): read, check, plan and apply them; the settings file, `fabricctl settings` |
| [federation/](federation/) | Sites: the site-name rule; invitations, joining and the federation endpoint as they are built |

`cli.py` routes the `fabricctl` commands implemented here (setup, doctor, uninstall, reinstall, certs, tsig, acl,
dhcp, radius, vault, logs, images, …) to one function each; `__init__.py` is empty (package marker).
