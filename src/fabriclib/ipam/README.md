# fabriclib/ipam

The address manager (manual 1.10.4): every site's VLANs, subnets, ranges and addresses, one plan kept in the domain
(its `OU=networks`, each entry named with its site; the site's record and the domain's option set in
`CN=fabric,CN=System`, 1.10.4.32, 1.10.4.33). Ported onto 0.8.0's directory area by area (1.10.4.41). The rules
are pure functions checked before anything is written.

| File | What |
|---|---|
| `check_vlan.py` | A VLAN checked: ID 1-4094 and name, each unique in the site; purpose, notes, access |
| `check_subnet.py` | A subnet checked: an IPv4 network, its gateway, relay, no overlap in the domain without a reason |
| `check_range.py` | A range checked: kind, inside its subnet, no overlap; a dhcp range holds only reservations |
| `check_address.py` | An address checked: one claim each, only reservations in a dhcp range, MAC and DNS name rules; warnings |
| `check_block.py` | A site's number checked: 1-255, no other site's |
| `suggestions.py` | What fabric suggests: a VLAN's subnet, the split of a /24, a site's number |
| `read_plan.py` | The plan from the domain, read as this DC's agent account: one site's or every site's |
| `write_plan.py` | Checked changes written to the plan in the domain, as this DC's agent account (at a read-only DC's site, at its writable DC) |
| `add_vlan.py`, `set_vlan.py`, `remove_vlan.py` | A VLAN with its subnet added; its record (and a lone subnet's settings) changed; removed with its subnets |
| `add_subnet.py`, `set_subnet.py`, `remove_subnet.py` | A VLAN's further subnet added; a subnet's settings changed; one removed with its ranges and addresses |
| `add_range.py`, `remove_range.py` | A range added to a VLAN's subnet; one removed by its first address |
| `add_address.py`, `set_address.py`, `remove_address.py` | An address recorded, changed, removed |
| `set_block.py` | A site's number set |
| `show_plan.py` | One site's plan as text: its number, each VLAN with each of its subnets, ranges and addresses |
| `plan_rows.py` | A site's address table: gateways, recorded addresses, leases |
| `find_in_plan.py` | An address, name or MAC across every site's plan |
| `export_plan.py` | The address table as CSV |
| `add_dhcp_subnet.py`, `set_dhcp_subnet.py`, `remove_reservation_mac.py` | The old `fabricctl dhcp add-subnet`, `set-subnet` and `unreserve` as changes to the plan (their aliases, `dhcp/run_dhcp_alias`) |
| `subnets_to_plan.py` | The upgrade: a site's `dhcp.subnets` as the plan's changes, nothing it serves changed |
| `move_subnets_to_plan.py` | The upgrade's move: the settings' subnets into the plan once, recorded, `dhcp.subnets` removed (called from area 5 on) |
| `run_ipam_command.py` | `fabricctl ipam`: routes only (show, find, export, block, vlan, subnet, range, address; option, class and netboot to `options/`) |
| [options/](options/) | The DHCP options in the plan, client classes and netboot presets |
| [common/](common/) | Helpers the address manager's commands share |
