# fabriclib/ipam/common

Helpers shared by the address manager's commands.

| File | What |
|---|---|
| `edit_plan.py` | One change to a site's plan: read, checked, written as the site's agent, kept, audited |
| `new_subnet.py` | The changes that add a subnet to a VLAN: checked, its gateway, Kea id and suggested split (vlan add, subnet add) |
| `change_subnet.py` | The change to a subnet's settings, checked, its gateway claimed by nothing else (vlan set, subnet set) |
| `fields.py` | The plan's fields and shared checks: one-line text, notes, addresses, finding a VLAN, a subnet or an address |
| `site_plan.py` | One site's plan and number out of what the domain answered |
| `plan_cache.py` | The last plan this site read (`<config>/address-plan.json`): where, read, write |
| `plan_holds_subnets.py` | Whether the subnets live in the plan (0.7's subnet commands are aliases then, their web forms refuse) |
| `option_codes.py` | The standard DHCPv4 option names and codes (Kea 3.0), and the options fabric provides |
| `pool_text.py` | A 0.7 pool as typed ("first - last") split into its two addresses |
| `site_scope.py` | The site a console request names, refused unless it is this one or one below it |
