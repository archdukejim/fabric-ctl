# fabriclib/ipam/common

Helpers shared by the address manager's commands (manual 1.10.4).

| File | What |
|---|---|
| `edit_plan.py` | One change to a site's plan: the grant checked, read, checked, written at the right DC, kept, audited |
| `edit_options.py` | One change to the DHCP options in the plan: the grant checked (at `all` for the domain's set), read, checked, written at the right DC, kept, audited |
| `plan_cache.py` | The last plan this site read (`<config>/address-plan.json`, 0600): where, read, write |
| `fields.py` | The plan's fields and shared checks: one-line text, notes, addresses, finding a VLAN, a subnet or an address |
| `new_subnet.py` | The changes that add a subnet to a VLAN: checked, its gateway, Kea id and suggested split (vlan add, subnet add) |
| `change_subnet.py` | The change to a subnet's settings, checked, its gateway claimed by nothing else (vlan set, subnet set) |
| `site_plan.py` | One site's plan, its number and its option sets out of what the domain answered (read_plan, 1.10.4.32) |
| `option_codes.py` | The one DHCPv4 option list (Kea 3.0's, by code and name) and the options fabric provides |
| `pool_text.py` | A 0.7 pool as typed ("first - last") split into its two addresses |
| `scan_busy.py` | `ScanBusy`: a scan refused only for now (one running, the same subnet within the minute); a request through AD stays pending |
