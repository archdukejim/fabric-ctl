# jinja/freeradius

Optional 802.1X (design §6). FreeRADIUS 3.2 from Debian's packages; every
decision is fabric's policy, which asks the site's domain controller (AD) about the device.

| File | What |
|---|---|
| `docker-compose.yml.j2` | The `freeradius` container: uid 610, no capabilities, read-only, UDP 1812/1813 on the host IP (and TCP 2083 while a client uses RadSec), on fabric_net; the DC's winbind sockets, privileged pipe and `smb.conf` read-only (PEAP) |
| [`packaging/images/freeradius/`](../../packaging/images/freeradius/) | The image: Debian's freeradius + python3 module + python3-ldap on the pinned Debian base; fabric's uid/gid |
| `config/radiusd.conf.j2` | Main configuration: fabric's own minimal tree, logs to the journal (decisions, never passwords) |
| `config/clients.conf.j2` | RADIUS clients (switches, APs) with their secrets from OpenBao; Message-Authenticator required unless relaxed |
| `config/fabric-radius.json.j2` | Where the policy finds the DC (LDAPS to fabric_net's gateway, verified: 2.1.2.15), its read-only account `fabric-radius-<site>`, and the groups mapped for password logins |
| `config/mods/always.j2` | `ok` (accounting is acknowledged, not stored) |
| `config/mods/eap.j2` | EAP-TLS (fabric CA only, no session resumption; the verify step that records each certificate's fingerprint); EAP-TTLS and PEAP only while a group is mapped |
| `config/mods/mschap.j2` | PEAP's MS-CHAPv2, checked by the domain through `ntlm_auth` and the DC's winbind |
| `config/mods/fabric_policy.j2` | The python3 module that runs `python/fabric_radius.py` |
| `config/sites/fabric.j2` | The server switches talk to over RADIUS/UDP: EAP, or MAB (in the client vendor's shape) for everything else; accounting logged as sessions |
| `config/sites/radsec.j2` | RadSec (TCP 2083) for the clients that use it: the client's own certificate (CN `radsec-<name>`), then the same decisions |
| `config/sites/inner-tunnel.j2` | Inside the tunnel: EAP-TTLS's user name and password, decided by the policy; PEAP's MS-CHAPv2 by the domain, then the policy (people and machines) |
| `config/sites/check-eap-tls.j2` | Runs the policy once a client certificate chained to the fabric CA; its VLAN goes into the Access-Accept |
| [`src/containers/freeradius/`](../../src/containers/freeradius/) | fabric's policy code (the python3 module's scripts, installed as `python/`): EAP-TLS by linked certificate, MAB by MAC, people by password; listed in that folder's README |

Rendered and copied to `<deploy_base>/freeradius/` by `fabriclib/radius/deploy_freeradius.py`
(config and python root:freerad 0640); tested by `tests/freeradius/run.py`.
