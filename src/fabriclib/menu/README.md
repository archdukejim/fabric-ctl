# fabriclib/menu

The vars editor: `fabricctl --interactive` (and `fabricctl` alone), `--print` and `--apply`, split out of the old
`lib/interactive.py` (now only their entry point). Every change is saved at once under the vars lock and audited.

| File | What |
|---|---|
| `run_vars_menu.py` | The top menu: the screens below, add or delete a setting, apply (asks first when a network setting changed) |
| `apply_and_report.py` | `--apply`: run the deploy engine, report the settings that changed and the services it restarted |
| `print_vars.py` | `--print`: list the top-level settings |
| `edit_dns.py` | The zones; add or remove a zone (served or dropped in seconds) |
| `edit_dns_zone.py` | One zone: its sync state and records, add or delete a record (validated by `fabriclib/dns`), live or forced update |
| `edit_list_of_dicts.py` | Add, change or delete entries of a list setting (TSIG keys, LDAP groups, OUs) |
| `edit_complex_variable.py` | The editor for a dict or list setting picked on a category screen |
| `edit_category.py` | A category screen: list its settings, edit one (immutable ones refused) |
| `edit_links.py` | The landing page links (`link-vars.yaml`) |
| `mint_certificate_menu.py` | Describe an extra certificate, record it in `extra_certs` and mint it (`pki/mint_extra_cert`) |
| `save_menu_change.py` | Save the working copy under the vars lock and audit the change; who is acting |
| `parse_value.py` | Typed text → YAML value (null, booleans, integers) |
| `constants.py` | Immutable and network-sensitive settings, the services screen's keys, the list editors' fields |
