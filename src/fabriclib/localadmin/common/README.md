# fabriclib/localadmin/common

Helpers shared by the local-admin functions.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `bao_call.py` | One OpenBao call that must succeed |
| `utc_now.py` | The time now in UTC, and a stored time read back |
| `local_admin_token.py` | A fabric-setup token, or why OpenBao cannot give one now (unreachable, sealed) |
| `account_exists.py` | Whether a local account of a name exists on this host |
| `rotation_due.py` | When the next password is due: the grace after the first use or check-out |
| `admin_group.py` | The group that gives local-admin its sudo here (`sudo`, else `wheel`) |
