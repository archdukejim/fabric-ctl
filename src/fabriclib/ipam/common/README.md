# fabriclib/ipam/common

Helpers shared by the address manager's commands.

| File | What |
|---|---|
| `edit_plan.py` | One change to a site's plan: read, checked, written as the site's agent, kept, audited |
| `edit_options.py` | One change to the DHCP options in the plan: read, checked, written at a writable DC, kept, audited |
| `option_codes.py` | The standard DHCPv4 options by Kea name and code, and the ones fabric provides (shared with the Networks tab) |
| `new_subnet.py` | The changes that add a subnet to a VLAN: checked, its gateway, Kea id and suggested split (vlan add, subnet add) |
| `change_subnet.py` | The change to a subnet's settings, checked, its gateway claimed by nothing else (vlan set, subnet set) |
| `fields.py` | The plan's fields and shared checks: one-line text, notes, addresses, finding a VLAN, a subnet or an address |
| `site_plan.py` | One site's plan and number out of what the domain answered |
| `plan_cache.py` | The last plan this site read (`<config>/address-plan.json`): where, read, write |
| `plan_holds_subnets.py` | Whether the subnets live in the plan (0.7's subnet commands refuse then) |
