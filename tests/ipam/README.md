# tests/ipam

The `ipam` suite (manual 1.10.4.3, 1.10.4.41): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, the site's number, several subnets on one VLAN, adding and changing a subnet, the small parts (0.7 pools, the option list, `ScanBusy`), one site's plan out of read_plan's answer on 0.8.0's directory, the address table, find, export and show, one change made the way every command makes it (the grant first, the writable DC, nothing written on a refusal), and `fabricctl ipam`'s refusals that need no domain. Areas 5 and 6 of the port add their sections |
| `options.py` | The DHCP options in the plan (decisions 2.1.10.23 to 2.1.10.25, manual 1.10.4.24 to 1.10.4.26): the option sets' checks and merge, where a change works (0.8's `org` read as `domain`), the netboot presets' checks and Kea classes, the provenance of each option, one option change made the way every option command makes it (the grant's networks options right first, at `all` for the domain's set), and `fabricctl ipam option`, `class` and `netboot`'s refusals that need no domain |
