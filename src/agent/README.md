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
| `get_route.py` | GET routes: one fabriclib read each (the Networks tab: `/v1/networks[/<site>[/export]]`) |
| `post_route.py` | POST routes by area; apply, people, login events |
| `post_dns.py` | Zones (add, remove), their records, TSIG keys |
| `post_dns_filter.py` | The DNS filter's lists, rules and upstreams (saved and applied), the lists job, the query-log search |
| `post_dhcp.py` | DHCP: reservations, subnets (name, VLAN, notes, pools), options, client classes, each applied at once |
| `post_ipam_scan.py` | The scan of a subnet, recording an address it found (a reservation for its MAC, or static, applied at once), and a scan asked at a site below |
| `post_local_scan.py` | Whether a site below may scan locally, set from this site above it (2.1.10.30) |
| `post_ipam_sync.py` | Sync now: the plan poll at once, and BIND's records when DNS waits |
| `post_options.py` | The DHCP options in the plan: options, classes, definitions (a site's; the organisation's with dhcp:org-options), netboot, who edits the organisation's |
| `post_network.py` | 802.1X settings, each applied at once |
| `post_networks.py` | The Networks tab: a site's number, VLANs, subnets, ranges and addresses (this site's applied at once; a site this console does not show refused) |
| `post_pki.py` | Manual PKI: describe or sign a CSR, issue, inspect, convert |
| `post_enrol.py` | Device enrolment: an Apple profile with a one-time SCEP challenge, a PKCS#12, withdrawing an unused profile (1.5.3) |
| `post_ssh.py` | SSH certificates: sign a fabric admin's key, turn them on or off (1.6.11.9) |
| `post_vault.py` | OpenBao's unlock methods, rotating the vault key |
| `post_directory.py` | Devices and device roles in the domain |
| `read_text.py` / `read_strings.py` / `read_fields.py` | Checked fields of a request body |
| `route_not_found.py` | `RouteNotFound`: the handler answers 404 |
| `__init__.py` | Empty; makes `agent` a package |
| `README.md` | This file |
| `post_domain.py` | The domain section: the site's machines (pre-create, enable, disable, remove) and its admin settings GPO |
| `post_host_access.py` | Host groups (create, delete, machines in and out) and sudo rules (add, remove), in the directory at once (1.6.11.7) |
| `post_security.py` | POST /v1/security/raise and /kerberos: raise a sign-in layer or turn Kerberos sign-in on or off, then apply |
| `job_store.py` | Background jobs (doctor, an image update): started by one call, followed by id, read only by who started them; kept in memory |
