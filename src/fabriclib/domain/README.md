# fabriclib/domain

Domain management (manual 1.6.12.17; Volume 4: 4.6.11): a person's details and lockout, groups and their two
levels, the admins' own OUs, a computer's folder, type and sites, a service's keytab command, the Kerberos facts and a
person's own password. Each function is one fabric-agent route's body and one `fabricctl domain` command's: it asks
fabric-agent's check (`fabriclib/access`), then one operation inside the DC, then audits.

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `edit_person.py` | A person's details changed (`people:edit`, AD's standard attributes, 2.1.6.93), audited `PERSON_EDIT` |
| `person_fields.py` | A person's fields (name -> AD attribute) and their checks |
| `show_person.py` | One person as the DC has them: their groups and details |
| `person_overview.py` | One person as their page shows them: details, state, last sign-in, groups, sites, certificates, devices |
| `directory_overview.py` | The Directory's Overview: the domain, its level and DCs, replication, sites, counts |
| `domain_facts.py` | The domain's functional level and its DCs |
| `my_account.py` | My account, read-only: the signed-in person's details, groups, certificates and devices |
| `unlock_person.py` | A person's lockout cleared (`people:reset`), audited `PERSON_UNLOCK` |
| `group_name_refused.py` | Why a new group's name is refused: its form, fabric's names, AD's |
| `create_group.py` | An admin's own group in OU=groups with a gid, audited `GROUP_CREATE` |
| `remove_group.py` | An admin's own group deleted, refused while in use, audited `GROUP_REMOVE` |
| `set_group_managers.py` | A group's managers and their controls (level 1), audited `GROUP_MANAGERS` |
| `list_groups.py` | The domain's groups and their kinds |
| `show_group.py` | One group's two levels: what it grants, its managers, its members |
| `my_groups.py` | The groups a person manages (My account's Groups I manage) |
| `list_ous.py` | The domain's OUs by path, fabric's marked, what each holds |
| `create_ou.py` | An admin's own OU, audited `OU_CREATE` |
| `rename_ou.py` | An admin's own OU renamed, audited `OU_RENAME` |
| `delete_ou.py` | An empty admin's own OU deleted, audited `OU_REMOVE` |
| `move_machine.py` | A computer moved to a folder under OU=machines, audited `MACHINE_MOVE` |
| `set_machine_type.py` | A computer's type group (and, asked, its type's folder), audited `MACHINE_TYPE` |
| `set_machine_site.py` | A computer put in a site's group or taken out, audited `MACHINE_SITE_ADD` / `_REMOVE` |
| `keytab_command.py` | The `fabric-keytab` command for a machine's administrator to run over SSH; nothing changed |
| `list_spns.py` | Every service principal and its account, duplicates flagged |
| `change_own_password.py` | A person's own password, as the person, at once; their other sessions ended |
| `read_options.py` | The CLI's `--option value` pairs, unknown ones refused |
| `run_person_command.py` | `fabricctl domain person edit\|unlock\|disable\|enable`: parses and routes |
| `run_group_command.py` | `fabricctl domain group list\|create\|delete\|scope\|managers\|members`: parses and routes |
| `run_ou_command.py` | `fabricctl domain ou list\|create\|rename\|delete`: parses and routes |
| `run_machine_command.py` | `fabricctl domain machine move\|type\|sites\|keytab`: parses and routes |
| `run_kerberos_command.py` | `fabricctl domain kerberos show\|spns\|policy`: parses and routes |
