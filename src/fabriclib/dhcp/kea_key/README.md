# fabriclib/dhcp/kea_key

Kea's DNS key, replaced within a year (decision 2.1.10.42, manual 1.10.4.43; the BIND STIG's V-272414).

| File | What |
|---|---|
| `kea_key.py` | The key as the secrets hold it: its name, secret, age and the key being replaced; the ages (330, 300, 365) |
| `start_key_rotation.py` | The first step, before an apply renders: a key dated, or replaced once due or when asked (a new name and secret; the old one kept for BIND) |
| `drop_old_key.py` | The last step, once Kea runs on the new key: BIND rendered without the old one, reconfigured, then the old key removed from the secrets; audited |
| `key_reminders.py` | What `fabricctl doctor` says: from day 300, due, under way, past the year |
| `rotate_key.py` | `fabricctl dhcp rotate-key`: replaced now, by the apply's steps |
