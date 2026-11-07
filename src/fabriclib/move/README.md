# fabriclib/move

The host's coming move announced to the machines fabric manages (manual
[1.4.1.8.7](../../../docs/volume_1_description_and_architecture/1.4.1-dns-architecture.md), procedure
[4.2.4.2](../../../docs/volume_4_operations/4.2.4-move-rename.md), decision
[2.1.1.79](../../../docs/volume_2_engineering_decisions/2.1.1-product.md)).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `check_new_address.py` | What may be announced: an IPv4 address on the host's LAN, not the host's own, on an install with no linked sites |
| `move_request.py` | One operation inside the DC (`src/containers/samba/move_tool.py`), the request on stdin |
| `run_move_command.py` | `fabricctl move prepare\|status\|cancel`: routes, audits and prints |
