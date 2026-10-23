# tests/settings

The `settings` suite (manual 1.8.5.9): the setup wizard and its settings file, with no container.

| File | What |
|---|---|
| `run.py` | The model: the file's round trip, the keys an import ignores by reason, every wizard key refused with why (nothing changed), the plan (changes, parts, the memory plan), a stale plan refused, the apply written and audited, the wizard's fields both ways, `fabricctl settings` export and import; DHCP turned on with its first subnet (the host's interfaces, the plan, the apply and its firewall refresh) |
| `console.py` | The agent's routes and their permission (settings:admin, the admin bundle only), the plan and its Apply as a job, a stale plan made again; the web console's steps, the plan page, Apply after a recent sign-in only, import and export, Finish setting up and the first sign-in opening the wizard |
