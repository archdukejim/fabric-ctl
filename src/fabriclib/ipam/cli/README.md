# fabriclib/ipam/cli

`fabricctl ipam`'s parts below its router, `ipam/run_ipam_command` (manual 1.10.4.16, 1.10.4.35): each routes to the
plan's functions, which hold every rule.

| File | What |
|---|---|
| `args.py` | The flags `fabricctl ipam` knows, and the readers of their values (positionals and flags, on/off, a value kept or cleared) |
| `run_plan_read.py` | `show`, `find`, `export`, and `block` without a number: any site of the domain |
| `run_plan_change.py` | `block <n>` and `vlan`, `subnet`, `range` and `address` `add`, `set` and `remove`, run as root |
| `report_change.py` | After a change: its warnings, then applied here, or left to the other site's plan poll |
