# tests/backup

The backup suite (`sudo tests/run-all.sh backup`; manual
[1.3.7.14](../../docs/volume_1_description_and_architecture/1.3.7-backups.md)). Root: owners and extended attributes are
checked; `age` and `zstd` are needed (the package depends on them).

| File | What |
|---|---|
| `bundle_test.py` | A bundle made, checked and opened with the real age, zstd and tar: passphrase and public key, wrong keys, a changed byte, nothing written plain |
| `section_of_key_test.py` | Every vars.yaml key belongs to exactly one section |
| `section_paths_test.py` | What each section packs; every folder fabric installs is in one |
| `prune_bundles_test.py` | Keeping the newest scheduled bundles; the others never removed |
| `run_backup_command_test.py` | `fabricctl backup`: routing, the key never an argument, one backup at a time |
| `schedule_test.py` | The schedule in vars.yaml and its timer's units: on, changed, refused, off |
