# tests/images

| File | What |
|---|---|
| `run.sh` | The suite: runs the three below, then the build plan (`packaging/docker-bake.hcl`) against a default host's rendered compose files, an unpinned base refused, every image built and smoke tested, the smoke test refusing the upstream step-ca (decision 2.1.1.21, manual 3.14.1) |
| `published.py` | Which image a host runs, rendered through the real templates: local builds without digests, published images with them, a local build again for custom ids (2.1.14.5); each image setting and `image_pins` as the compose files use them; the lock's ids against the Dockerfiles and defaults (manual 1.14.3) |
| `verify.py` | Signature verification against real keyless signatures: a signed image verifies with its signer and is refused with fabric's; fabric's published image verifies with fabric's; unsigned, unreachable and unpinned refs refused; the deploy step and its opt-out (2.1.14.6, 2.1.14.10, 2.1.14.11) |
| `commands.py` | `fabricctl images` without an install: alone it is the status; unknown subcommands, extra words, an unknown service or one never updated (rollback) refused with why; prune on images only it makes (an old one removed, one in use and other repositories kept) and `image_prune` on and off (2.1.14.3) |
| `update.sh` | Every image's update and rollback from one version back, on an installed host (the sandbox kept with `KEEP=1`, or a test host over SSH): moved back by an update, status showing the update, update, rollback, update again, each health-gated; images with no earlier version skipped with the reason; then all current and doctor passing (2.1.14.12). Run for a release candidate, once its images are published and pinned |
| `previous.yaml` | One version back for each image `update.sh` moves: the previous upstream version on its track, or the previous release of fabric's own images; and the images skipped, with why |
| `host_images.py` | On the host, for `update.sh`: the image status rows as JSON, and pinning a validated image in the installed lock |
