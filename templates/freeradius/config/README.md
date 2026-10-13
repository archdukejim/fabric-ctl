# jinja/freeradius/config

FreeRADIUS configuration, rendered by `fabriclib/radius/deploy_freeradius.py`
to `/opt/freeradius/config/<name>` (root:freerad 0640) and mounted read-only
at `/etc/freeradius/fabric`. `deploy_freeradius` also writes `ad-password`
(the site's `fabric-radius-<site>` account's password) here.

| Path | What |
|---|---|
| `radiusd.conf.j2` | Main configuration: fabric's own minimal tree, logs to the journal (decisions, never passwords) → `radiusd.conf` |
| `clients.conf.j2` | RADIUS clients (switches, APs) with their secrets from fabric's secrets; Message-Authenticator required unless relaxed; RadSec clients in their own list (`clients radsec`) → `clients.conf` |
| `fabric-radius.json.j2` | For the policy: the DC's URI (LDAPS to the host's address, verified), CA file, the site's read account and its password file, the domain's DN and the site, groups mapped for password logins, each client's vendor rules (MAB shape, VLAN attributes) → `fabric-radius.json` |
| [mods/](mods/) | Modules: `always`, `eap`, `fabric_policy` → `mods/` |
| [sites/](sites/) | Virtual servers: `fabric`, `radsec`, `check-eap-tls`, `inner-tunnel` → `sites/` |
