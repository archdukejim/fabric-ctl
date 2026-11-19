# fabriclib/backup

Backups: one encrypted bundle of seven sections, made by hand or on a schedule, restored whole or by section (manual
[1.3.7](../../../docs/volume_1_description_and_architecture/1.3.7-backups.md), decisions
[2.1.1.105, 2.1.1.106](../../../docs/volume_2_engineering_decisions/2.1.1-product.md) and
[2.1.3.6](../../../docs/volume_2_engineering_decisions/2.1.3-fabricctl.md)).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `backup_lock.py` | One backup or restore at a time: an exclusive lock held for the run |
| `backup_plan.py` | What each section packs, cold or online: the live databases left out, their dumps beside them |
| `backup_running.py` | Whether a backup or restore holds its lock now, and its pid |
| `bundle_key_from.py` | A bundle's own private key, opened from its key.age with the passphrase or the private key |
| `bundle_name.py` | A bundle's file name: host, UTC time, kind |
| `check_backup_space.py` | Refuse a bundle the disk cannot hold: twice what it copies must be free |
| `check_bundle.py` | Whether a bundle is whole: the manifest, key.age, the seven sections and each one's SHA-256 |
| `dump_directory.py` | The domain copied while the DC runs (`samba-tool domain backup offline`) |
| `dump_signin.py` | Keycloak's database dumped while it runs (`pg_dump -Fc` over the container's own socket) |
| `freeze_zones.py` | BIND's zones written out and held still while they are copied (`rndc freeze`, `thaw`) |
| `install_backup_timer.py` | fabric-backup.timer and its service as vars.yaml says, or removed |
| `list_bundles.py` | The bundles in the backups folder, newest first, from their names and manifests |
| `make_backup.py` | One bundle of the install, online or cold, one at a time, audited |
| `make_bundle.py` | One bundle: a fresh key pair, each section packed and encrypted to it, the key sealed, one plain tar |
| `make_bundle_key.py` | A new age key pair for one bundle, in memory |
| `open_bundle_key.py` | key.age opened with the passphrase or the schedule's private key |
| `open_section.py` | One section unpacked into place (`age -d \| zstd -d \| tar -x`), owners, modes, ACLs and xattrs kept |
| `pack_section.py` | One section streamed `tar \| zstd \| age`, never written unencrypted |
| `pause_unit.py` | A service stopped while its files are copied, then started again |
| `prune_bundles.py` | Keep the newest scheduled bundles; never remove the others |
| `read_backup_key.py` | How a bundle is sealed or opened: a passphrase asked twice or read from stdin, a public key, a private key file |
| `read_manifest.py` | A bundle's manifest, read without any key |
| `run_age.py` | `age` with a passphrase typed on a pty of its own, never on its command line |
| `run_backup_command.py` | `fabricctl backup`, `list`, `check`, `schedule`: routes and prints |
| `save_vault_snapshot.py` | OpenBao's raft snapshot, taken with the fabric-backup AppRole |
| `seal_bundle_key.py` | The bundle's private key encrypted with a passphrase or to the schedule's public key |
| `section_of_key.py` | The one section that owns a vars.yaml key |
| `section_paths.py` | What one section packs: its folders, less the deeper ones another section claims |
| `sections.py` | The seven sections: what each holds, its vars.yaml keys, what depends on it |
| `set_backup_schedule.py` | The schedule's time, keep and public key in vars.yaml, then its timer |
