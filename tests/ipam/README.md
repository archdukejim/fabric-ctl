# tests/ipam

The `ipam` suite (manual 1.10.4.17): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, a plan rendered for Kea and checked by fabric, the upgrade's changes from 0.7 (nothing served changed, a second run changing nothing), the address table, find, export, and `fabricctl ipam`'s refusals that need no domain |
| `networks.py` | The Networks tab's model (manual 1.10.4.21): a subnet as a map (bar, counts, every address: the plan's, leases beside them, unrecorded leases, free runs), options with their sources and fabric's marker, the site scope, the agent's permission table for its routes, and the 0.7 subnet commands' alias refusals that need no domain |
| `scan.py` | The scan and ping-check with no container (2.1.10.26): only a subnet this site's DHCP serves (bad input, another subnet, a /21, DHCP off refused), one scan at a time and once a minute, what answered set beside the plan and Kea's leases, audited; the probe's fixed commands in Kea's container; the offer to record each find; `fabricctl ipam scan`; the agent's permissions and the console's scan page with their refusals; `dhcp.ping_check` and the template's hook |
| `options.py` | The DHCP options in the plan (decisions 2.1.10.23 to 2.1.10.25, manual 1.10.4.24 to 1.10.4.26): the option sets' checks and merge, where a change works, the netboot presets' checks and Kea classes (rendered by the Kea template to JSON), the provenance of each option, the plan poll's states with its steps stubbed, and the option commands' refusals that need no domain |
| `role_test.py` | 802.1X on the plan (1.11.1.7, 1.11.1.8): a reservation's device role (only a reservation; the role must exist; warnings without `network:mab` or on another VLAN), a role's VLAN checked against the plan, the plan's VLAN labels, the CSV's `role` column |
