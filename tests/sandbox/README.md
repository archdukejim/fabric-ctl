# tests/sandbox

A full install from the `.deb` in a disposable systemd + Docker container
(`sudo tests/run-all.sh sandbox`, about 30 min), then day-2 operations on it.

| File | What |
|---|---|
| `run.sh` | Install, setup (Docker from the Ubuntu archive, no apt source added), doctor, fabric.target, DHCP (a LAN client leased and registered in `dhcp.<domain>`, `fabricctl dhcp`: reservations, a named subnet with VLAN and notes, a client class with an option, an option Kea refuses before it is saved, removal keeping the first subnet's id), 802.1X (`fabricctl radius add-client`, a MAB request answered from the directory with the role's VLAN, `fabricctl radius log`, `map-group` turning EAP-TTLS on), undoing one host change (`setup --undo trust` refused unattended without `--yes`, then done: the CA out of the trust store, status showing it declined, doctor passing, `--approve trust` bringing it back; `--undo accounts` refused; the host's own files kept before fabric's first change), POSIX identities (fabric-admin's and the first Directory Administrator's; people created outside fabric through `fabricctl directory sync`), setup's administrators (D2: the vars file's first Directory Administrator and its refusals, fabric-admin's generated password in `~/fabric-admin/`, its sign-in by Kerberos and sudo on the DC's host, the Directory Administrator refused there, the tiers' password policies through `--tier`, `fabricctl admin reset-break-glass`, `fabricctl host accounts` (list, approve, unapprove) and doctor's reminders, each refused as anyone but root), secrets in OpenBao, OpenBao unlock/restart/rotation (core services serve while it is down), RFC2136, sign-in (admin, non-admin, auditor; the setup wizard opening on the admin's first Overview, then dismissed through the console), images update/rollback/prune, re-runs, upgrade of pre-pinning vars, TSIG/ACL, package upgrade/remove, reinstall, uninstall with export + purge (it lists every host change first; nothing left; chrony's own configuration back, ufw as it was before fabric), restore from the export |
| `move.sh` | The release's move test (2.1.1.60, 2.1.1.61; 3.3.5), in a sandbox of its own: 0.7.1 built from its tag and set up by its own setup, its records and a TSIG key's rights checked, its vars.yaml copied off; uninstalled with an export; the candidate installed and set up with that file: refused unattended naming the first administrator's keys, then, with them, the same zones, records, keys' rights and parts, a new root CA and new TSIG secrets (the old one refused), doctor |
| `move_state.py` | Inside the move test's sandbox: what the move keeps (zones, the records as BIND serves them, the TSIG keys' rights, the parts) and makes new (the root CA's and the TSIG secrets' hashes) |
| `Dockerfile` | The sandbox image (systemd + Docker-in-Docker) |
| `login_test.py` | Real sign-in through nginx, Keycloak (password change, TOTP) and the web UI, and the refusals; OpenBao's UI through Keycloak; a role bundle through a directory group; adding a person and resetting a sign-in |
| `rfc2136_test.sh` | `nsupdate` with a TSIG key: allowed name accepted and served, other names and wrong keys refused |
| `certs_page_test.sh` | The certificate page: formats, MIME types, plain HTTP by name and IP |
| `set_lock.py` | Pretend a newer validated image list arrived (edit the installed `images.lock.yaml`) |
| `radius_mab.py` | A switch's MAB request (with Message-Authenticator) from outside the sandbox: Accept + VLAN, Reject, or no reply |
| `radius_device.py` | Inside the sandbox: VLAN 30 on the default `printers` role and a printer in it, with fabric's own directory code |
| `list_roles.py` | Inside the sandbox: the device roles' names (the defaults setup created) |
| `iterate.sh` | Developer helper: re-run parts against a kept sandbox |
| `make_person.py` | A person of the site made the way fabric makes them, optionally in an organisation group |
| `agent_job.py` | Inside the sandbox: one fabric-agent job (doctor, an image update) through its socket, as the web console runs it |
