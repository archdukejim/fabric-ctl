# fabriclib/directory/common

Helpers shared by the device, role, people, host group and sudo rule operations.

| File | What |
|---|---|
| `read_directory.py` | This site's devices and the device roles it may use, raw, in one call (operation `read_devices`) |
| `check_device_fields.py` | Validate a device's type, MACs (unique across devices), owner, description, roles |
| `check_role_fields.py` | Validate a role's permissions, VLAN, priority, description |
| `normalize_mac.py` | Any common MAC spelling → `aa:bb:cc:dd:ee:ff`; refuses multicast |
| `check_host_group_name.py` | A host group's short name, given short or as `<site>-hosts-<name>` (1.6.11.7) |
| `check_sudo_rule.py` | Validate a sudo rule's name, who, commands, as whom and host group (1.6.11.7) |
| `person_guard.py` | Who may change a person's sign-in: fabric groups only by an admin, never yourself, never the last admin |
