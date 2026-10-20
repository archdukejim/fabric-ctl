# fabriclib/hostaccounts

The local root and administrator accounts of a host that runs a DC (manual 1.6.13.6, 1.6.12.16.7; decisions 2.1.6.78,
2.1.7.15): listed from the host's own files, reminded of until removed or approved as break glass by root acting for
the Enterprise Admin.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `constants.py` | The record's name, the admin groups, the system files read |
| `approvals.py` | The host's record (`<config>/local-accounts.json`): the setup account and the approvals, read and written |
| `record_setup_user.py` | The account that ran setup recorded once, as the host's root break glass for now |
| `list_local_admins.py` | Every local account with root or administrator rights: uid 0, the sudo/wheel/admin groups, sudoers ALL |
| `local_account_reminders.py` | The reminder of each one not approved (the console, `fabricctl doctor`) |
| `approve_local_account.py` | An account approved as break glass (audited `LOCAL_ACCOUNT_APPROVE`) |
| `unapprove_local_account.py` | An approval withdrawn (audited `LOCAL_ACCOUNT_UNAPPROVE`) |
| `run_host_command.py` | `fabricctl host accounts` (`list`, `approve <name>`, `unapprove <name>`): parses and routes |
