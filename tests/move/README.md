# tests/move

Pure tests of `fabricctl move` (manual 4.2.4.2, 4.2.4.8; decision 2.1.1.79), in the `consent` suite. The announce
inside the DC is `tests/samba/linux_join.py`'s.

| File | What |
|---|---|
| `check_new_address_test.py` | Which address may be announced: on the LAN, or on another subnet named with `--network`; each refusal |
| `run_move_command_test.py` | `move prepare <address> [--network <subnet>]`: the words read, the network audited, wrong forms refused |
