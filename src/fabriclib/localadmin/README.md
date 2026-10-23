# fabriclib/localadmin

The fabric host's own `local-admin` (manual 1.7.1.4; decisions 2.1.7.15 to 2.1.7.20): a local account in `sudo`,
its password generated and kept by OpenBao, rotated after use, checked out only by the Enterprise Admin, and let in
over SSH only while the domain's switch for its host is on.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `constants.py` | The account's name, the record, OpenBao's mount and password policy, the policies, the grace, the SSH drop-in |
| `record.py` | The host's record (`<config>/local-admin.json`): what fabric made and saw, never a password |
| `secret_path.py` | Where the host's local-admin lives in OpenBao's `local-admin/` mount |
| `ensure_local_admin_store.py` | OpenBao's mount `local-admin/` and its password policy |
| `set_local_admin_password.py` | A new password: generated, kept in OpenBao, set with chpasswd, then marked current |
| `read_local_admin_secret.py` | What OpenBao holds: the current version, its policy, and (a check-out) its password |
| `ensure_local_admin.py` | The account made (only fabric's own) and its first password set (setup's step) |
| `find_local_admin_uses.py` | Its sign-ins since a time, from the journal's PAM session lines and wtmp |
| `check_local_admin.py` | The hourly run: a use marked, a rotation after the grace (waiting while OpenBao is locked), SSH applied |
| `checkout_local_admin.py` | Its password checked out by the Enterprise Admin, with a reason (audited; rotated after use) |
| `set_local_admin_policy.py` | Its rotation policy: after-use or keep-until-checkout (audited) |
| `require_enterprise_admin.py` | The Enterprise Admin's tier, or a refusal (root, or AD's top tier as the DC says) |
| `local_admin_request.py` | One operation on the switches kept in the domain, inside the DC (`local_admin_tool.py`) |
| `read_ssh_switch.py` | The SSH switch of a DC's host as the domain keeps it |
| `set_local_admin_ssh.py` | The SSH switch set in the domain by the Enterprise Admin, applied here at once (audited) |
| `apply_local_admin_ssh.py` | The switch applied to sshd: its drop-in, checked with `sshd -t`, sshd reloaded |
| `local_admin_status.py` | What `fabricctl local-admin status` shows |
| `local_admin_checks.py` | Doctor's check and the warnings (a rotation waiting, a failed run) |
| `remove_local_admin.py` | The host change undone: the account, its home, the drop-in and the record removed |
| `run_local_admin_command.py` | `fabricctl local-admin` (`status`, `checkout`, `policy`, `ssh`, `check`): parses and routes |
| `common/` | Helpers shared by the files above (see its README) |
