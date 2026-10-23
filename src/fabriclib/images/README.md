# fabriclib/images

Container images on the host (design [1.14.2](../../../docs/volume_1_description_and_architecture/1.14.2-image-updates.md#11421-status), 2.1.14.3).
Every image is pinned by digest; the validated list is `config/images.lock.yaml`
of the installed fabric. Nothing here runs on its own: a fabric upgrade keeps
the images a host runs, and only `fabricctl images update` moves them.

| File | What |
|---|---|
| `constants.py` | Managed services in update order (unit, container, image var, local build, published image) and the rollback and verified-digest files |
| `installed_services.py` | The managed services this install has |
| `built_from.py` | The base a local fabric image was built FROM (its `org.fabric.base` label) |
| `needs_rebuild.py` | Whether a compose file's local image is missing or built from another base than its pinned one |
| `running_image.py` | What a service runs now (container image, or the base of its local build) |
| `image_status.py` | Per service: running, set, validated, and the state (current / update available / held / …) |
| `switch_image.py` | Move a service (and any sharing its base) to a ref: pull, render, compose down/up per service, health-gated, rolled back on failure |
| `update_images.py` | Move services to their validated images (skips images the admin set, unless forced) |
| `rollback_image.py` | Back to the image before the last update |
| `prune_images.py` | Remove old images of fabric's repositories: not pinned, not the rollback image, not used by any container |
| `run_images_command.py` | `fabricctl images status / update / rollback / prune / export / import` |
| `published_image.py` | The one rule: does this host run fabric's published image or build its own (ids must match, 2.1.14.5) |
| `effective_service.py` | A managed service as this host runs it (published image: its own var, no local build) |
| `verify_signature.py` | `cosign verify` (pinned image) of a published image against fabric's signer; verified digests remembered |
| `remember_verified.py` | Record digests whose signature verified (online, or offline from a bundle) |
| [bundle/](bundle/) | Offline install bundles: `images export`, `images import`, setup's `bundle` step (manual 1.14.4) |
| `apply_image_action.py` | One service updated or rolled back, from the web console (the job behind its Updates section) |
