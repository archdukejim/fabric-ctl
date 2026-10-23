# tests/dhcp

DHCP's own units with no container, run with the `ipam` suite (manual 1.10.4.20).

| File | What |
|---|---|
| `clean_names_test.py` | DHCP names left behind for addresses named by hand (2.1.10.22): the addresses set by hand, kept for the hourly timer (0600), the records of DHCP's zone left behind for them, their deletion in one signed update with nsupdate and BIND's container stood in for (nothing sent when nothing is stale, refused without Kea's key or when BIND refuses, nothing audited then), and `fabricctl dhcp clean-names`'s positive and negative cases. Against a real BIND and Kea: `tests/kea/run.py` |
