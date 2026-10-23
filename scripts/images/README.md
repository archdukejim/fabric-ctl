# scripts/images

| File | What |
|---|---|
| `pin_published.py` | Writes a publish's verified multi-arch digests (both architectures, signed by fabric's images workflow), with each image's source hash, into the lock's `published:` section (manual 3.14.1.4) |
| `source_hash.py` | Each fabric image's source hash (its staged build context and pinned base); `--check` refuses a published image whose sources changed and that is not marked `pending` (2.1.14.13) |
| `trusted_root.py` | Sigstore's trusted root shipped in the package (`config/sigstore-trusted-root.json`) for offline signature checks; `--check` says whether it is current (manual 1.14.4.6) |
