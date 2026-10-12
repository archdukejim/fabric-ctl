# fabriclib/ipam

The address manager (manual 1.10.4): every site's VLANs, subnets, ranges and addresses, one plan kept in the domain
(`OU=networks` of each site), read and written as the site's agent account; Kea and the site's static names rendered
from it at every apply. The rules are pure functions checked before anything is written.

| File | What |
|---|---|
| `check_vlan.py` | A VLAN checked: ID 1-4094 and name, each unique in the site; purpose, notes, access |
| `check_subnet.py` | A subnet checked: an IPv4 network, its gateway, relay, no overlap in the organisation without a reason |
| `check_range.py` | A range checked: kind, inside its subnet, no overlap; a dhcp range holds only reservations |
| `check_address.py` | An address checked: one claim each, only reservations in a dhcp range, MAC and DNS name rules; warnings |
| `suggestions.py` | What fabric suggests: a VLAN's subnet, the split of a /24, a site's number |
| `plan_to_dhcp.py` | A site's plan as Kea's `dhcp.subnets` and the A records of its published addresses |
| `subnets_to_plan.py` | The upgrade's changes: 0.7's `dhcp.subnets` as VLANs, subnets, ranges and reservations |
| `plan_rows.py` | A site's address table: gateways, recorded addresses, leases |
| `find_in_plan.py` | An address, name or MAC across every site's plan |
| `export_plan.py` | The address table as CSV |
| `read_plan.py` | The plan from the domain (one site's or every site's) |
| `write_plan.py` | Checked changes written to the domain |
| `planned_subnets.py` | The DHCP subnets a site serves, from its settings or the plan it last read |
| `load_address_plan.py` | At an apply: the plan read (or the last one kept) into Kea's subnets and the site's zone |
| `move_subnets_to_plan.py` | The upgrade: a site's `dhcp.subnets` moved into its plan once, recorded |
| `add_vlan.py` | Add a VLAN with its subnet (suggested or given), gateway and the suggested ranges |
| `set_vlan.py` | Change a VLAN's record and its subnet's gateway, DHCP, relay, overlap reason |
| `remove_vlan.py` | Remove a VLAN with its subnet (refused while it records addresses, unless forced) |
| `add_range.py` | Add a range to a VLAN's subnet |
| `remove_range.py` | Remove a range by its first address |
| `add_address.py` | Record an address: static, reservation or infrastructure |
| `set_address.py` | Change a recorded address |
| `remove_address.py` | Remove a recorded address |
| `run_ipam_command.py` | `fabricctl ipam show / find / export / vlan / range / address` (applies a change to this site unless `--no-apply`) |
| `common/` | Helpers shared by the commands: the checked edit, the plan's fields, the kept copy |
