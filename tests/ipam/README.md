# tests/ipam

The `ipam` suite (manual 1.10.4.17): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, a plan rendered for Kea and checked by fabric, the upgrade's changes from 0.7 (nothing served changed, a second run changing nothing), the address table, find, export, and `fabricctl ipam`'s refusals that need no domain |
| `options.py` | The DHCP options in the plan (decisions 2.1.10.23 to 2.1.10.25, manual 1.10.4.24 to 1.10.4.26): the option sets' checks and merge, where a change works, the netboot presets' checks and Kea classes (rendered by the Kea template to JSON), the provenance of each option, the plan poll's states with its steps stubbed, and the option commands' refusals that need no domain |
