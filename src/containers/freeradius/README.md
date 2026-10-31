# jinja/freeradius/python

fabric's 802.1X policy, run inside the `freeradius` container. Copied (not
rendered) by `fabriclib/radius/deploy_freeradius.py` to
`/opt/freeradius/python/` (root:freerad 0640), mounted read-only at
`/etc/freeradius/python`. Tested by `tests/freeradius/run.py`.

| File | What |
|---|---|
| `fabric_radius.py` | The policy module (`mods/fabric_policy`): EAP-TLS by linked certificate, MAB by MAC, people by password (EAP-TTLS), people and machines after PEAP (post-auth); the VLAN; fail closed; one `fabric:` log line per decision |
| `lookup_device.py` | Find a device by certificate fingerprint or MAC in the site's `OU=devices` (AD) and judge it (enabled, permission, VLAN by role priority) |
| `check_person.py` | Check a person's password by binding to AD as them (lockout applies) and their mapped groups (VLAN by priority) |
| `directory.py` | The policy's LDAPS connection to the site's DC: its DC's `fabric-radius-<dc>` account per thread, or a bind as a person |
| `record_fingerprint.py` | EAP-TLS verify command: SHA-256 fingerprint of the presented certificate, stored under its serial in `/run/freeradius/fp` |
| `normalize_mac.py` | Any MAC spelling → `aa:bb:cc:dd:ee:ff` |
| `check_peap.py` | Decide an account the domain accepted over PEAP: a person, or a machine of this site's `OU=machines`, in a mapped group (2.1.11.3) |
| `mappings.py` | An account's groups as mappings name them (those in `OU=groups`, plus the primary group) and the mapping it joins under |
