# fabriclib/ipam/options

The address manager's DHCP options (manual 1.10.4.24 to 1.10.4.26; decisions 2.1.10.23 to 2.1.10.25): the
organisation's and each site's option sets in AD, options at every level, client classes, custom definitions, the
provenance of what a client gets, netboot presets, the upgrade from the settings, and the pieces of the plan poll.

| File | What |
|---|---|
| `settings_options.py` | The options, definitions and classes the settings still carry (not moved into the plan yet) |
| `option_label.py` | An option's code, name and identity, by the one option list (`ipam/common/option_codes`) or a definition |
| `check_option_set.py` | An option set or one level's options checked: known names, definitions, classes (no `fabric-nb-` name) |
| `check_netboot.py` | A netboot preset checked: a boot server and at least one way to boot; warnings |
| `merge_option_sets.py` | The global level out of the organisation's, the site's and the settings' sets, the later replacing the earlier |
| `netboot_classes.py` | The Kea client classes the netboot presets need, per subnet and per reservation |
| `effective_options.py` | The provenance: every option a site, subnet or address ends up with, its source, what it overrides, the classes |
| `options_overview.py` | What the options page and `option show` show: the sets, the subnets' and reservations' options and presets |
| `show_options.py` | `fabricctl ipam option show` as text |
| `show_netboot.py` | `fabricctl ipam netboot show` as text |
| `scope_options.py` | The place an option change works on: organisation, site, subnet, class, address |
| `set_owner.py` | The option set a definition or class change works on: the organisation's or the site's |
| `netboot_targets.py` | What a netboot command works on: a VLAN's subnets, a subnet, a reservation |
| `set_plan_option.py` | Set an option at a level of the plan |
| `remove_plan_option.py` | Remove an option from a level of the plan |
| `define_plan_option.py` | Define an option Kea has no name for (organisation or site) |
| `undefine_plan_option.py` | Remove an option definition (refused while an option names it) |
| `add_plan_class.py` | Add a client class (organisation or site) |
| `remove_plan_class.py` | Remove a client class with its options |
| `set_netboot.py` | Switch a netboot preset on, or change it |
| `clear_netboot.py` | Switch a netboot preset off |
| `set_option_editor.py` | The top site lets a site edit the organisation's options, or stops it (`fabric-dhcp-org-editors`) |
| `move_options_to_plan.py` | The upgrade: the settings' global options, definitions and classes into the site's set once, recorded |
| `read_usn.py` | The DC's highest committed USN (the plan poll's first step; no secret) |
| `plan_digest.py` | What the plan poll compares: digests of Kea's input and DNS's, the served subnets |
| `watch_state.py` | The plan poll's kept states (`plan-watch.json`, `plan-dns.json`) |
| `render_kea.py` | Kea alone rendered from the settings and the plan, restarted when it changed (never a full apply) |
| `run_option_command.py` | `fabricctl ipam option / class / netboot / option-editors / watch` (routing only) |
