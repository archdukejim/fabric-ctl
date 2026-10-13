# tests/ipam

The `ipam` suite (manual 1.10.4.17): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, a plan rendered for Kea and checked by fabric, the upgrade's changes from 0.7 (nothing served changed, a second run changing nothing), the address table, find, export, and `fabricctl ipam`'s refusals that need no domain |
| `networks.py` | The Networks tab's model (manual 1.10.4.21): a subnet as a map (bar, counts, every address: the plan's, leases beside them, unrecorded leases, free runs), options with their sources and fabric's marker, the site scope, the agent's permission table for its routes, and the 0.7 subnet commands' alias refusals that need no domain |
