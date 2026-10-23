# fabriclib/ipam/options

The address manager's DHCP options (manual 1.10.4.24 to 1.10.4.26; decisions 2.1.10.23 to 2.1.10.25): the
domain's and each site's option sets in the domain (1.10.4.32), options at every level, client classes, custom
definitions, the provenance of what a client gets, and netboot presets. Each change is checked against the grants'
networks options right first (1.10.4.34). Ported in area 4 (1.10.4.41); the upgrade from the settings and the plan
poll come with later areas.

| File | What |
|---|---|
| `settings_options.py` | The options, definitions and classes the settings still carry (not moved into the plan yet) |
| `option_label.py` | An option's code, name and identity, by the one option list (`ipam/common/option_codes`) or a definition |
| `check_option_set.py` | An option set or one level's options checked: known names, definitions, classes (no `fabric-nb-` name) |
| `check_netboot.py` | A netboot preset checked: a boot server and at least one way to boot; warnings |
| `merge_option_sets.py` | The global level out of the domain's, the site's and the settings' sets, the later replacing the earlier |
| `netboot_classes.py` | The Kea client classes the netboot presets need, per subnet and per reservation |
| `effective_options.py` | The provenance: every option a site, subnet or address ends up with, its source, what it overrides, the classes |
| `options_overview.py` | What `option show` (and later the options page) shows: the sets, the subnets' and reservations' options and presets |
| `show_options.py` | `fabricctl ipam option show` as text |
| `show_netboot.py` | `fabricctl ipam netboot show` as text |
| `scope_options.py` | The place an option change works on: the domain, the site, a subnet, a class, an address |
| `set_owner.py` | The option set a definition or class change works on: the domain's or the site's |
| `netboot_targets.py` | What a netboot command works on: a VLAN's subnets, a subnet, a reservation |
| `set_plan_option.py` | Set an option at a level of the plan |
| `remove_plan_option.py` | Remove an option from a level of the plan |
| `define_plan_option.py` | Define an option Kea has no name for (the domain's set or a site's) |
| `undefine_plan_option.py` | Remove an option definition (refused while an option names it) |
| `add_plan_class.py` | Add a client class (the domain's set or a site's) |
| `remove_plan_class.py` | Remove a client class with its options |
| `set_netboot.py` | Switch a netboot preset on, or change it |
| `clear_netboot.py` | Switch a netboot preset off |
| `run_option_command.py` | `fabricctl ipam option / class / netboot` (routing only) |
