def upgrade_vars(data, pinned):
    """Purpose: adjust an existing install's vars before a newer fabric re-renders them, so an upgrade never
             changes a running image (design 2.1.14.3).
    Inputs:  data — the existing vars dict (modified in place); pinned — collection of image_* keys the admin
             set explicitly (left alone).
    Returns: list of change descriptions (str), one per image_* key dropped. Keys pinned by digest ("@sha256:")
             are kept; unpinned refs and local build names not in `pinned` are deleted, so the release's validated,
             digest-pinned default applies. (What it changed for installs before 0.8.0 is retired: 2.1.1.61, the
             stale-code register 2.3.1.5.2.)
    Fails:   never — dict operations only.
    Feeds:   collect_vars (logs each change).
    Notes:   `fabricctl images update` is what changes images (design 2.1.14.3)."""
    changes = []
    for key in [k for k in data if k.startswith("image_") and k != "image_pins" and k not in pinned]:
        if isinstance(data[key], str) and "@sha256:" in data[key]:
            continue
        del data[key]
        changes.append(f"{key}: use this release's validated image (pinned by digest)")
    return changes
