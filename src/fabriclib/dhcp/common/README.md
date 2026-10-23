# fabriclib/dhcp/common

Helpers shared by the DHCP commands.

| File | What |
|---|---|
| `edit_dhcp.py` | One checked change to `dhcp:` in vars.yaml: locked, normalized (ids stored), checked by Kea before it is saved, audited |
| `find_subnet.py` | The subnet a command names, by name or network |
| `option_target.py` | Where an option goes: every subnet, a subnet, a client class or a reservation |
| `kea_image.py` | The Kea image this host runs (published or its local build), to check Kea files with |
| `apply_dhcp_change.py` | A just-recorded DHCP or address-plan change applied now (unless `--no-apply`), then the host firewall brought in line; `fabricctl dhcp` and `fabricctl ipam` share it |
| `hand_set_path.py` | Where the last apply keeps the addresses set by hand for the hourly cleanup (`<deploy base>/kea/hand-set.json`) |
| `turn_dhcp_on.py` | The `dhcp` settings DHCP is turned on with, checked and not saved (`fabricctl dhcp on`; once the subnets live in the plan, the plan's) |
