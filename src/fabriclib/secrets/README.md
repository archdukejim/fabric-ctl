# fabriclib/secrets

fabric's own secrets (generated passwords, TSIG and RADIUS secrets, …): where
they live and how they are read and changed. Before the `vault` setup step
they are in the 0600 file `/opt/fabric/config/fabric-secrets.yml`; the step
moves them into OpenBao (KV v2 `fabric/secrets`) and from then on OpenBao
is the source of truth (marker `/opt/fabric/config/secrets.openbao`). A
secrets file put back later (a reinstall restores one) wins and is
re-imported.

| File | What |
|---|---|
| `constants.py` | The OpenBao path and the marker file name |
| `held_secrets.py` | What fabric-agent keeps of OpenBao's answer, for a minute; forgotten when it writes them (2.1.8.35) |
| `secrets_in_openbao.py` | True once the marker exists (a missing file then never means "no secrets") |
| `load_secrets.py` | Read them from the file or OpenBao; OpenBao locked → error, never an empty set |
| `save_secrets.py` | Change them where they live (top-level keys; `tsig_secrets` and `radius_secrets` merged key by key; OpenBao check-and-set) |
| `import_secrets.py` | File → OpenBao: write, read back, compare, then write the marker and shred the file |
| `export_secrets.py` | A root-only 0600 copy for a reinstall's backup (setup re-imports and shreds it) |
| `run_secrets_command.py` | `fabricctl secrets list` (names) / `show <name>` (one value, audited) |
| `random_secret.py` | A new random secret from the OS's CSPRNG (base64, or 32 letters and digits) |
| `random_password.py` | A new random password every allowed policy accepts (64 characters, both cases and digits) |
| `common/` | OpenBao read/write of the `fabric/secrets` entry (see its README) |
