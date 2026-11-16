# tests/openbao

| File | What |
|---|---|
| `run.py` | OpenBao from fabric's own templates on the real pinned image: vault key and unlock methods (key file, USB stick on a loop device, security key on SoftHSM2, HSM on a PyKMIP server), rotation (including a KMIP device that stops answering part way, and the second `rotate` that finishes it, 2.3.1.57), tampering, the kill switch, fabric's secrets, hardening, and `fabricctl vault …` itself (its prompts answered as a person would, secrets never on the command line) — including what must be refused |
| `kmip_server.py` | The PyKMIP server `run.py` starts as its stand-in HSM, with a session whose client has gone made to end: PyKMIP 0.10.0 looped without end on it under Python 3.14 (Ubuntu 26.04) and stopped answering (2.3.1.57) |
| `db_rotation.py` | Keycloak's database password rotated by OpenBao, against the real Postgres and OpenBao images: the take-over (own admin, Keycloak's own role owning its data, the bootstrap role locked), a rotation, converging without change, the refusals (2.1.7.4) |
| `local_admin.py` | The fabric host's local-admin (1.7.1.4) against the real OpenBao image, configured by fabric (fabric-setup's real policy): the mount and password policy, the first password current only once the host took it, a foreign account refused, a use seen in the journal and wtmp and the rotation after the grace, a host refusing the new password, check-out (its reason, audited, rotated after), the two policies, OpenBao sealed (the rotation waits, a check-out refused, rotated once unsealed), the SSH drop-in and its refusals, a DC host's break-glass rename (`fabricctl admin rename-host`: local-admin follows the name, each refusal changing nothing, 2.1.6.104), the undo |

`run.py` needs Docker, root, `losetup`, `softhsm2` + `python3-pykcs11` (security keys)
and `python3-pykmip` (HSM): `sudo apt install softhsm2 python3-pykcs11 python3-pykmip`.
