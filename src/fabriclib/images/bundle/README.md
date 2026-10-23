# fabriclib/images/bundle

Offline install bundles (decision 2.1.14.14, manual [1.14.4](../../../../docs/volume_1_description_and_architecture/1.14.4-offline-bundles.md#1144-offline-install-bundles)):
`fabricctl images export` on a machine with internet, `fabricctl images import` and `setup --offline <bundle>` on a
host without. Nothing is fetched on import, and nothing is loaded before it checks.

| File | What |
|---|---|
| `bundle_images.py` | What a bundle carries: every image of the lock, upstream ones by name and fabric's published ones as `fabric/<name>` |
| `registry_name.py` | Where an image repository lives (registry host, path, the full name Docker gives it) |
| `fetch_blob.py` | One blob or manifest from a registry by digest, checked against it as it arrives (anonymous token, redirects without it) |
| `image_size.py` | How large one image is for one architecture, from its manifests alone |
| `fetch_image.py` | One image for one architecture as an OCI layout tar: its own index (the lock's digest), manifest, config, layers |
| `cosign_run.py` | Run the pinned cosign image locked down, with or without network |
| `fetch_signature.py` | A published image's Sigstore signature bundle, from beside it in the registry |
| `fetch_trusted_root.py` | Sigstore's trusted root, through cosign's verified TUF fetch (for the copy the package ships, `scripts/images/trusted_root.py`) |
| `free_bytes.py` | Free space on the filesystem holding a path |
| `export_bundle.py` | `images export`: the bundle file (images, signatures, manifest), refused before it starts when it cannot be whole |
| `check_bundle.py` | Everything provable without Docker: whole, version, architecture, every pinned image and its digests, every hash |
| `host_arch.py` | This host's architecture as Debian names it |
| `verify_offline.py` | A published image's carried signature checked with no network (cosign, the trusted root the package ships) |
| `import_bundle.py` | `images import` / setup's `bundle` step: check, room, signatures, then load; images already there are kept |
| `describe_import.py` | The lines printed for an import's result |
