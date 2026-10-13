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
| `check_block.py` | A site's number checked: 1-255, no other site's |
| `suggestions.py` | What fabric suggests: a VLAN's subnet, the split of a /24, a site's number |
| `show_plan.py` | One site's plan as text: its number, each VLAN with each of its subnets, ranges and addresses |
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
| `set_vlan.py` | Change a VLAN's record, and the subnet's settings of a VLAN with one subnet |
| `remove_vlan.py` | Remove a VLAN with its subnets (refused while they record addresses, unless forced) |
| `set_block.py` | Set or change a site's number (what fabric suggests from then on) |
| `add_subnet.py` | Add another subnet to a VLAN (or a first one to a VLAN kept as a record) |
| `set_subnet.py` | Change a subnet's gateway, DHCP, relay, notes, overlap reason |
| `remove_subnet.py` | Remove one subnet with its ranges and addresses (refused while it records addresses, unless forced) |
| `add_range.py` | Add a range to a VLAN's subnet |
| `remove_range.py` | Remove a range by its first address |
| `add_address.py` | Record an address: static, reservation or infrastructure |
| `set_address.py` | Change a recorded address |
| `remove_address.py` | Remove a recorded address |
| `scannable_subnets.py` | The subnets a scan may cover: this site's DHCP subnets, each at most a /22 |
| `scan_subnet.py` | Scan one served subnet on request: what answers, set beside the plan and Kea's leases; one at a time, once a minute; audited |
| `show_scan.py` | A scan's result as text, with the command that would record each find |
| `offer_reservations.py` | After a scan on a terminal: "make it a reservation?" (or static) for each find, through `add_address` |
| `run_ipam_command.py` | `fabricctl ipam show / find / export / block / vlan / subnet / range / address / scan` (applies a change to this site unless `--no-apply`) |
| `common/` | Helpers shared by the commands: the checked edit, the plan's fields, the kept copy |
| `visible_sites.py` | The sites this console shows and edits: its own, then those that joined below it |
| `subnet_map.py` | A subnet as the Networks tab draws it: its ranges as a bar, its counts, every address (free runs too) |
| `fabric_options.py` | The options fabric provides at a subnet: router, DNS, NTP, the domain, its search list |
| `subnet_options.py` | The options a subnet ends up with and where each came from (provided by fabric, overridden) |
| `networks_view.py` | What the Networks tab shows of one site, drawn from a plan (pure) |
| `networks_overview.py` | The Networks tab's read: a site's plan from the domain (or the kept copy), its leases, drawn |
| `networks_csv.py` | The Networks tab's CSV export of a site's address table |
| `add_dhcp_subnet.py` | 0.7's `dhcp add-subnet` as one plan change: the VLAN if new, the subnet, its pools as ranges |
| `set_dhcp_subnet.py` | 0.7's `dhcp set-subnet` as one plan change: router, notes, overlap reason, pools added and removed |
| `remove_reservation_mac.py` | 0.7's `dhcp unreserve <mac>`: the reservation that MAC holds removed from the plan |
