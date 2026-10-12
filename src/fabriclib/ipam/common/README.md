# fabriclib/ipam/common

Helpers shared by the address manager's commands.

| File | What |
|---|---|
| `edit_plan.py` | One change to a site's plan: read, checked, written as the site's agent, kept, audited |
| `fields.py` | The plan's fields and shared checks: one-line text, notes, addresses, finding a VLAN or an address |
| `site_plan.py` | One site's plan and number out of what the domain answered |
| `plan_cache.py` | The last plan this site read (`<config>/address-plan.json`): where, read, write |
| `plan_holds_subnets.py` | Whether the subnets live in the plan (0.7's subnet commands refuse then) |
