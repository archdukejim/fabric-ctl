# src/agent

`fabric-agent` is the root daemon behind the web UI. It runs on the host
(systemd `fabric-agent`) and serves a fixed, permission-checked JSON API over a
unix socket mounted into the unprivileged `fabric-web` container: every route
maps to one fabriclib operation, callers are checked by peer uid and by the
signed-in person's Keycloak token, and every change is audited. It never runs
arbitrary commands.

| File | What |
|---|---|
| `server.py` | Entry point (systemd): the socket server (root:webui 0660) and the route list |
| `handler.py` | One request: peer uid (SO_PEERCRED), token and permission (`fabriclib/rbac`), body and actor, errors as JSON replies |
| `get_route.py` | GET routes: one fabriclib read each |
| `post_route.py` | POST routes by area; apply, people, login events |
| `post_pending.py` | Apply per page (manual 1.8.6.5): holding a change, dropping, discarding and applying a page's changes as one job |
| `pending_store.py` | The pending store (2.1.8.13): each person's changes per page, Apply in order stopping at the first failure, refusing a change whose thing changed since, a check of the change's own at hold and at Apply (the address manager's grant), the page's queue |
| `landing_note.py` | DNS' Review's sentence when the landing page's certificate waits for a full apply (2.1.8.29) |
| `pending_thing.py` | What a held change changes: its page, its words, the thing's read and its version (2.1.8.14) |
| `pending_dns.py` | DNS' held changes in a sentence (moved from `pending_thing.py`) |
| `pending_networks.py` | The address manager's held changes (1.10.4.40.2): their page (Networks, DHCP options), sentence, thing and key, and the grant's networks right at their site |
| `post_dns.py` | Zones (add, remove), their records, TSIG keys (a new key or secret given to BIND at once, 2.1.8.24) |
| `post_dns_filter.py` | The DNS filter's lists, rules and upstreams (saved and applied), the lists job, the query-log search |
| `post_dhcp.py` | DHCP: reservations, subnets (name, VLAN, notes, pools), options, client classes, each applied at once |
| `post_network.py` | 802.1X settings, each applied at once |
| `post_networks.py` | The address plan's changes (`/v1/networks/<site>/...`): each the ipam function the CLI calls, the grant checked there; this site's applied at once |
| `post_options.py` | The DHCP options in the plan, client classes, definitions and netboot presets (the domain's set as `scope` domain) |
| `post_ipam_sync.py` | Sync now: the plan poll at once, and BIND's records when DNS waits |
| `post_ipam_scan.py` | A scan of this site's subnet, a find recorded, a scan asked of another site |
| `post_pki.py` | Manual PKI: describe or sign a CSR, issue, inspect, convert |
| `post_vault.py` | OpenBao's unlock methods, rotating the vault key |
| `post_directory.py` | Devices and device roles in the domain |
| `read_text.py` / `read_strings.py` / `read_fields.py` | Checked fields of a request body |
| `one_thing.py` | A read of one person, computer, group or grant: its "not there" refusal answered 404 (2.1.8.21). |
| `route_not_found.py` | `RouteNotFound`: the handler answers 404 |
| `__init__.py` | Empty; makes `agent` a package |
| `README.md` | This file |
| `post_domain.py` | The domain section: the site's machines (pre-create, enable, disable, remove) and its admin settings GPO |
| `post_grants.py` | The grants (1.6.13.7): add, change, remove, compile now (`groups:admin`) |
| `post_people.py` | A person (1.6.12.17.6): edit, unlock, reset, disable, enable, remove, groups, add; each checked by fabric-agent for the token's caller |
| `post_groups.py` | Groups: create, delete, managers (`groups:admin`), members (the DC decides: the tier above, or a manager) |
| `post_ous.py` | The admins' own OUs: create, rename, delete (`ous:admin`) |
| `post_account.py` | A person's own account: their password, as them, at once (any sign-in) |
| `post_host_access.py` | Host groups (create, delete, machines in and out) and sudo rules (add, remove), in the directory at once (1.6.11.7) |
| `post_local_admin.py` | The DC host's local-admin: its check-out and its SSH switch, the Enterprise Admin's alone (1.7.1.4.5, 1.7.1.4.6) |
| `post_security.py` | POST /v1/security/raise and /kerberos: raise a sign-in layer or turn Kerberos sign-in on or off, then apply |
| `job_store.py` | Background jobs (doctor, an image update): started by one call, followed by id, read only by who started them; kept in memory |
| `post_settings.py` | POST /v1/settings/plan, /apply and /dismiss: the setup wizard's plan, its apply as a job (a stale plan made again), the wizard dismissed |
| `plan_store.py` | The setup wizard's plans waiting for their Apply: by id, only for who made them, 15 minutes; kept in memory |
