# fabriclib/breakglass

`fabric-admin`, the Enterprise Admin and break-glass account (manual 1.6.12.2, 1.6.13.6; decisions 2.1.6.68, 2.1.6.69,
2.1.6.75): made by setup with a generated password written once to `~/fabric-admin/`, a reminder while that file
exists, and the reset by root on a host with a writable DC.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `constants.py` | The account's name, the password's length and safe special characters, the file's and record's names |
| `break_glass_password.py` | A new generated password: 24 characters of letters, digits and `- _ . , : + = @ ^ ~`, each class at least once |
| `ensure_enterprise_admin.py` | fabric-admin made once at the root's DC, inside it as the system, in AD's top tier (not in directory-admins) |
| `write_break_glass_file.py` | The password written once to `~/fabric-admin/fabric-admin-password.txt` (0700/0600, the person's), its path recorded |
| `break_glass_reminder.py` | While that file exists: the reminder to store it and delete it; once gone, its removal audited |
| `reset_break_glass.py` | A lost password replaced on a host with a writable DC: a new one set inside the DC, the account unlocked, the file written again, audited `BREAK_GLASS_RESET` |
| `run_admin_command.py` | `fabricctl admin reset-break-glass`: parses and routes to reset_break_glass |
