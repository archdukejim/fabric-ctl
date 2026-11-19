# fabriclib/backup

Backups: one encrypted bundle of seven sections, made by hand or on a schedule, restored whole or by section (manual
[1.3.7](../../../docs/volume_1_description_and_architecture/1.3.7-backups.md), decisions
[2.1.1.105, 2.1.1.106](../../../docs/volume_2_engineering_decisions/2.1.1-product.md) and
[2.1.3.6](../../../docs/volume_2_engineering_decisions/2.1.3-fabricctl.md)).

| File | What |
|---|---|
| `__init__.py` | Package marker |
| `bundle_key_from.py` | A bundle's own private key, opened from its key.age with the passphrase or the private key |
| `bundle_name.py` | A bundle's file name: host, UTC time, kind |
| `check_bundle.py` | Whether a bundle is whole: the manifest, key.age, the seven sections and each one's SHA-256 |
| `make_bundle.py` | One bundle: a fresh key pair, each section packed and encrypted to it, the key sealed, one plain tar |
| `make_bundle_key.py` | A new age key pair for one bundle, in memory |
| `open_bundle_key.py` | key.age opened with the passphrase or the schedule's private key |
| `open_section.py` | One section unpacked into place (`age -d \| zstd -d \| tar -x`), owners, modes, ACLs and xattrs kept |
| `pack_section.py` | One section streamed `tar \| zstd \| age`, never written unencrypted |
| `read_manifest.py` | A bundle's manifest, read without any key |
| `run_age.py` | `age` with a passphrase typed on a pty of its own, never on its command line |
| `seal_bundle_key.py` | The bundle's private key encrypted with a passphrase or to the schedule's public key |
| `section_of_key.py` | The one section that owns a vars.yaml key |
| `section_paths.py` | What one section packs: its folders, less the deeper ones another section claims |
| `sections.py` | The seven sections: what each holds, its vars.yaml keys, what depends on it |
