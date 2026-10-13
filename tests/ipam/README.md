# tests/ipam

The `ipam` suite (manual 1.10.4.17): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, a plan rendered for Kea and checked by fabric, the upgrade's changes from 0.7 (nothing served changed, a second run changing nothing), the address table, find, export, and `fabricctl ipam`'s refusals that need no domain |
| `scan.py` | The scan and ping-check with no container (2.1.10.26): only a subnet this site's DHCP serves (bad input, another subnet, a /21, DHCP off refused), one scan at a time and once a minute, what answered set beside the plan and Kea's leases, audited; the probe's fixed commands in Kea's container; the offer to record each find; `fabricctl ipam scan`; the agent's permissions and the console's scan page with their refusals; `dhcp.ping_check` and the template's hook |
