# jinja/freeradius/config/mods

Rendered to `/opt/freeradius/config/mods/<name>` by
`fabriclib/radius/deploy_freeradius.py`.

| File | What |
|---|---|
| `always.j2` | The `ok` module (accounting is acknowledged once the policy has logged it) → `always` |
| `eap.j2` | EAP-TLS (fabric CA only, no session resumption; its verify step runs `python/record_fingerprint.py`); EAP-TTLS and PEAP (EAP-MSCHAPv2) only while a group is mapped → `eap` |
| `fabric_policy.j2` | The python3 module that loads `python/fabric_radius.py` (instantiate, authorize, post_auth, accounting) → `fabric_policy` |
| `mschap.j2` | MS-CHAPv2 checked by the domain through `ntlm_auth` and the DC's winbind (rendered raw) → `mschap` |
