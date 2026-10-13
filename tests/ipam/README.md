# tests/ipam

The `ipam` suite (manual 1.10.4.17): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, a plan rendered for Kea and checked by fabric, the upgrade's changes from 0.7 (nothing served changed, a second run changing nothing), the address table, find, export, and `fabricctl ipam`'s refusals that need no domain |
| `role_test.py` | 802.1X on the plan (1.11.1.7, 1.11.1.8): a reservation's device role (only a reservation; the role must exist; warnings without `network:mab` or on another VLAN), a role's VLAN checked against the plan, the plan's VLAN labels, the CSV's `role` column |
