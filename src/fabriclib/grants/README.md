# fabriclib/grants

Grants: who may do what, where, by overlapping groups (manual 1.6.13.4 to 1.6.13.7; decisions 2.1.6.73, 2.1.6.77,
2.1.6.87). The store, the checks and the compiler run inside the DC (`src/containers/samba/grants_tool.py`); these
functions ask it, audit, and route the CLI.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `grant_request.py` | One grants operation inside the DC, with this DC's name and whether it is the root's writable DC |
| `read_grant_fields.py` | A grant's fields from a request body or the CLI's options, their types checked |
| `list_grants.py` | The grants and the templates, whom each reaches as counts |
| `show_grant.py` | One grant: the people and machines it reaches by name, its groups, its sets, its sudo rule |
| `add_grant.py` | A new grant (from a template or none), compiled at once, audited `GRANT_ADD` and `GRANT_COMPILE` |
| `set_grant.py` | A grant changed, compiled at once, audited `GRANT_SET` |
| `remove_grant.py` | A grant removed, the rest compiled at once, audited `GRANT_REMOVE` |
| `explain_grant.py` | Which grants reach a person (and on a machine), and why |
| `sync_grants.py` | The grants compiled again: at once after fabric changes a group's members, and by the fabric-grants timer |
| `run_grant_command.py` | `fabricctl domain grant list\|show\|add\|set\|remove\|explain\|sync`: parses and routes |
