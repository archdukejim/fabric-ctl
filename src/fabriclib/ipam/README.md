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
| `move_subnets_to_plan.py` | The upgrade's move: the settings' subnets into the plan once, recorded, `dhcp.subnets` removed (called by every apply and by setup) |
| `run_ipam_command.py` | `fabricctl ipam`: routes only (sync, scan; the reads and changes to `cli/`; option, class, netboot and watch to `options/`; scan at another site and scan-requests to `scancontrol/`) |
| [cli/](cli/) | `fabricctl ipam`'s arguments, its reads of the plan and its changes |
| `networks_overview.py` | What the Networks tab shows of a site: its plan drawn, the sites, leases, scan requests, the Sync now card; the kept copy when the DC is down |
| `networks_view.py` | A site's plan as the Networks tab draws it: each subnet's map and its options with their sources |
| `subnet_map.py` | One subnet drawn: its ranges as a bar, the counts, every address accounted for |
| `networks_csv.py` | The Networks tab's CSV export of a site's address table |
| `scannable_subnets.py` | The subnets a scan may cover here (at most a /22) |
| `scan_overview.py` | What the scan page shows: those subnets, and whether the person may scan here |
| `plan_to_dhcp.py` | A site's plan as Kea's `dhcp.subnets` and the A records of its published addresses |
| `planned_subnets.py` | The DHCP subnets a site serves, from its settings or the plan it last read |
| `load_address_plan.py` | At an apply: the plan read (or the last one kept) into Kea's subnets and the site's zone |
| `poll_plan.py` | One run of the plan poll (fabric-plan-watch.timer): the USN, the scans other sites asked for, then Kea alone re-rendered when its input changed |
| `scan_subnet.py` | A scan of one subnet of this site's plan: the caller's `scan` right checked, one at a time, what answered set beside the plan and the leases, audited |
| `show_scan.py` | A scan's result as text, with the command that records each find |
| `offer_reservations.py` | After a scan on a terminal: asked, for each find, whether to record it |
| [sync/](sync/) | Sync now: the plan poll at once, and the plan's DNS by the quick path |
| [options/](options/) | The DHCP options in the plan, client classes and netboot presets |
| [scancontrol/](scancontrol/) | Scans at another site: requested through AD, answered by that site's poll |
| [common/](common/) | Helpers the address manager's commands share |
