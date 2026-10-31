# tests/openbao

| File | What |
|---|---|
| `run.py` | OpenBao from fabric's own templates on the real pinned image: vault key and unlock methods (key file, USB stick on a loop device, security key on SoftHSM2, HSM on a PyKMIP server), rotation, tampering, the kill switch, fabric's secrets, hardening, and `fabricctl vault …` itself (its prompts answered as a person would, secrets never on the command line) — including what must be refused |

Needs Docker, root, `losetup`, `softhsm2` + `python3-pykcs11` (security keys)
and `python3-pykmip` (HSM): `sudo apt install softhsm2 python3-pykcs11 python3-pykmip`.
| `db_rotation.py` | Keycloak's database password rotated by OpenBao, against the real Postgres and OpenBao images: the take-over (own admin, Keycloak's own role owning its data, the bootstrap role locked), a rotation, converging without change, the refusals (2.1.7.4) |
| `local_admin.py` | The fabric host's local-admin (1.7.1.4) against the real OpenBao image, configured by fabric (fabric-setup's real policy): the mount and password policy, the first password current only once the host took it, a foreign account refused, a use seen in the journal and wtmp and the rotation after the grace, a host refusing the new password, check-out (its reason, audited, rotated after), the two policies, OpenBao sealed (the rotation waits, a check-out refused, rotated once unsealed), the SSH drop-in and its refusals, the undo |
