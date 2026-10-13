# tests/openbao

| File | What |
|---|---|
| `run.py` | OpenBao from fabric's own templates on the real pinned image: vault key and unlock methods (key file, USB stick on a loop device, security key on SoftHSM2, HSM on a PyKMIP server), rotation, tampering, the kill switch, fabric's secrets, hardening, and `fabricctl vault …` itself (its prompts answered as a person would, secrets never on the command line) — including what must be refused |

Needs Docker, root, `losetup`, `softhsm2` + `python3-pykcs11` (security keys)
and `python3-pykmip` (HSM): `sudo apt install softhsm2 python3-pykcs11 python3-pykmip`.
| `db_rotation.py` | Keycloak's database password rotated by OpenBao, against the real Postgres and OpenBao images: the take-over (own admin, Keycloak's own role owning its data, the bootstrap role locked), a rotation, converging without change, the refusals (2.1.7.4) |
| `ssh_ca.py` | SSH certificates for the fabric admins against the real OpenBao image (1.6.11.9, 2.1.7.12): on and off through fabric-agent's routes (the engine, an Ed25519 CA, the 8-hour role, the published key, the setting), a fabric admin's key signed (ssh-keygen -L: principal, CA, validity), the refusals (not an admin, root, a private key, DSA, short RSA, two keys, off, sealed, a setup policy predating it). Written for 0.9, not run yet |
