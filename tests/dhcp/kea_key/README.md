# tests/dhcp/kea_key

Kea's DNS key replaced within a year (decision 2.1.10.42, manual 1.10.4.43), no container; run with the `ipam` suite. Against real Kea and BIND: `tests/kea/reload.py`.

| File | What |
|---|---|
| `kea_key_test.py` | The key's name, age and the key being replaced, as the secrets hold them |
| `start_key_rotation_test.py` | Dated at the first apply, replaced from day 330 or when asked (a name of its own), nothing while one is under way, with DHCP or its registration off, or before a key exists |
| `drop_old_key_test.py` | BIND's keys and grants rendered from fabric's templates without the old key, reconfigured, then the secrets and the audit; BIND refusing keeps the old key |
| `key_reminders_test.py` | doctor: from day 300, due from 330, failed past 365, under way, not dated |
| `rotate_key_test.py` | `fabricctl dhcp rotate-key`: saved and audited before the apply, its refusals, the CLI's output and exit codes |
