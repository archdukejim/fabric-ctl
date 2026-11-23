# tests/backup

The backup suite (`sudo tests/run-all.sh backup`; manual
[1.3.7.14](../../docs/volume_1_description_and_architecture/1.3.7-backups.md)). Root: owners and extended attributes are
checked; `age` and `zstd` are needed (the package depends on them).

| File | What |
|---|---|
| `bundle_test.py` | A bundle made, checked and opened with the real age, zstd and tar: passphrase and public key, wrong keys, a changed byte, nothing written plain |
| `old_address_uses_test.py` | What still names the old address or subnet after a move; fabric's own and other networks left out |
| `prune_bundles_test.py` | Keeping the newest scheduled bundles; the others never removed |
| `restore_test.py` | A whole restore of a real bundle with address changes, its refusals, and the dump loaders |
| `restore_section_test.py` | One section restored on a running install, its refusals, and `fabricctl restore --section` |
| `run_backup_command_test.py` | `fabricctl backup`: routing, the key never an argument, one backup at a time |
| `schedule_test.py` | The schedule in vars.yaml and its timer's units: on, changed, refused, off |
| `section_of_key_test.py` | Every vars.yaml key belongs to exactly one section |
| `section_paths_test.py` | What each section packs; every folder fabric installs is in one |
| `schedule_status_test.py` | The schedule's settings and runs from systemd's words, and with no systemd |
| `start_console_restore_test.py` | The console's whole restore started as its own unit, the key never on its command line; the checks before anything stops |
