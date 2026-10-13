# jinja/freeradius/config/sites

Rendered to `/opt/freeradius/config/sites/<name>` by
`fabriclib/radius/deploy_freeradius.py`.

| File | What |
|---|---|
| `fabric.j2` | The server switches talk to over RADIUS/UDP: EAP, or MAB (the policy by MAC, in the client vendor's shape) for everything else; accounting logged as sessions (1.11.1.4) → `fabric` |
| `check-eap-tls.j2` | Runs the policy once a client certificate chained to the fabric CA; its VLAN goes into the Access-Accept → `check-eap-tls` |
| `inner-tunnel.j2` | Inside EAP-TTLS: marks the request `Tmp-String-0 = fabric-people` and lets the policy check the person's user name and password → `inner-tunnel` |
| `radsec.j2` | RadSec (RADIUS over TLS, TCP 2083) for the clients that use it: a client certificate from the fabric CA with CN `radsec-<client name>`, then the same decisions as `fabric`; empty while no client uses RadSec (manual 1.11.1.3) → `radsec` |
