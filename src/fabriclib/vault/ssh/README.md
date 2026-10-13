# fabriclib/vault/ssh

OpenBao's SSH certificate authority for the fabric admins (manual 1.6.11.9; decisions 2.1.7.5, 2.1.6.39, 2.1.7.12):
off by default, turned on in the web console, 8-hour user certificates with the person's user name as the one
principal, trusted by managed machines through the published CA key.

| File | What |
|---|---|
| `constants.py` | The engine's mount, the signing role and its settings, the lifetime, the published file, the key types signed |
| `set_ssh_certificates.py` | The console's toggle: OpenBao converged, the setting saved, the CA key published or withdrawn, audited |
| `converge_ssh_ca.py` | OpenBao to the setting: on (engine, CA key once, role) or off (role deleted; CA kept) |
| `publish_ssh_ca.py` | The CA's public key at `/certs/ssh-user-ca.pub`, or removed (machines then stop trusting it) |
| `sign_ssh_key.py` | An 8-hour certificate for a fabric admin's public key; everyone else refused and audited |
| `ssh_overview.py` | The SSH page: on or off, the CA key and fingerprint, whether this person may sign |
| `parse_ssh_key.py` | Read and judge one OpenSSH public key (Ed25519, ECDSA, RSA of 3072 bits and more) |
| `__init__.py` | Package marker (empty) |
