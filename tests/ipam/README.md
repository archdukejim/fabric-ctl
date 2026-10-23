# tests/ipam

The `ipam` suite (manual 1.10.4.3, 1.10.4.41): the address manager's model, with no container.

| File | What |
|---|---|
| `run.py` | The rules (VLANs, subnets and overlaps, ranges, one claim per address, only reservations in a dhcp range), the suggestions, the site's number, several subnets on one VLAN, adding and changing a subnet, the small parts (0.7 pools, the option list, `ScanBusy`), and one site's plan out of read_plan's answer on 0.8.0's directory. Areas 4 to 6 of the port add their sections |
