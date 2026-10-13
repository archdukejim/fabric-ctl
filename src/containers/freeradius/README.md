# jinja/freeradius/python

fabric's 802.1X policy, run inside the `freeradius` container. Copied (not
rendered) by `fabriclib/radius/deploy_freeradius.py` to
`/opt/freeradius/python/` (root:freerad 0640), mounted read-only at
`/etc/freeradius/python`. Tested by `tests/freeradius/run.py`.

| File | What |
|---|---|
| `fabric_radius.py` | The policy module (`mods/fabric_policy`): EAP-TLS by linked certificate, MAB by MAC in the client vendor's shape (a device's, else a DHCP reservation's), people by password (EAP-TTLS), people and machines after PEAP (post-auth), RadSec's wrong certificate refused; the VLAN; fail closed; one `fabric:` log line per decision, and one `fabric: ACCT` line per accounting request (the sessions) |
| `lookup_device.py` | Find a device by certificate fingerprint or MAC in the site's `OU=devices` (AD) and judge it (enabled, then its roles) |
| `judge_roles.py` | Judge the device roles an entry names for a permission: the union of their permissions, the VLAN by role priority (this site's and the organisation's roles) |
| `lookup_reservation.py` | MAB from a DHCP reservation (1.11.1.7): the reservation of the site's address plan holding a MAC, judged by the role it names; the VLAN is its subnet's |
| `check_person.py` | Check a person's password by binding to AD as them (lockout applies) and their mapped groups (VLAN by priority) |
| `directory.py` | The policy's LDAPS connection to the site's DC: its `fabric-radius-<site>` account per thread, or a bind as a person |
| `record_fingerprint.py` | EAP-TLS verify command: SHA-256 fingerprint of the presented certificate, stored under its serial in `/run/freeradius/fp` |
| `normalize_mac.py` | Any MAC spelling → `aa:bb:cc:dd:ee:ff` |
| `check_peap.py` | Decide an account the domain accepted over PEAP: a person, or a machine of this site's `OU=machines`, in a mapped group (2.1.11.3) |
| `mappings.py` | An account's groups as mappings name them (fabric's under `OU=sites`, plus the primary group) and the mapping it joins under |
| `check_mab.py` | Read a MAB request in its client vendor's shape (Cisco: Call-Check; UniFi: the MAC as password) |
| `vlan_reply.py` | The reply attributes that put a client on a VLAN (RFC 3580) |
