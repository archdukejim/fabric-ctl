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
| `post_dns.py` | Zone records, TSIG keys |
| `post_dns_filter.py` | The DNS filter's lists, rules and upstreams (saved and applied), the lists job, the query-log search |
| `post_dhcp.py` | DHCP: reservations, subnets (name, VLAN, notes, pools), options, client classes, each applied at once |
| `post_network.py` | 802.1X settings, each applied at once |
| `post_pki.py` | Manual PKI: describe or sign a CSR, issue, inspect, convert |
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
