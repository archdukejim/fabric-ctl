from fabriclib.deploy.keep_old_install import keep_old_install
from fabriclib.rbac.permissions import ADMIN_ROLE, OLD_ADMIN_ROLE
from fabriclib.setup.common.previous_accounts import PREVIOUS_ACCOUNTS


def upgrade_vars(data, pinned):
    """Purpose: adjust an existing install's vars before a newer fabric re-renders them, so an upgrade never
             changes a running image, and gets this release's service accounts.
    Inputs:  data — the existing vars dict (modified in place); pinned — collection of image_* keys the admin
             set explicitly (left alone).
    Returns: list of change descriptions (str), one per image_* key dropped and one per service account moved.
             Keys pinned by digest ("@sha256:") are kept; unpinned refs and local build names not in `pinned` are
             deleted, so the release's validated, digest-pinned default applies. service_users entries that are
             exactly a previous release's default (PREVIOUS_ACCOUNTS: same uid and gid, no name) are deleted, so
             the fabric-* account in the 600-649 band applies (the accounts step moves the files); entries the
             admin changed are kept. The console's admin role named fabric-admin (before 0.6.4) becomes
             fabric-console-admin: that name is now the first admin's (2.1.6.33); Keycloak and OpenBao follow at
             their steps, members kept. What an install from before 0.7.0 keeps (keep_old_install: its DC's name).
    Fails:   never — dict operations only.
    Feeds:   collect_vars (logs each change).
    Notes:   `fabricctl images update` is what changes images (design 2.1.14.3)."""
    changes = keep_old_install(data)
    for key in [k for k in data if k.startswith("image_") and k != "image_pins" and k not in pinned]:
        if isinstance(data[key], str) and "@sha256:" in data[key]:
            continue
        del data[key]
        changes.append(f"{key}: use this release's validated image (pinned by digest)")
    users = data.get("service_users")
    if isinstance(users, dict):
        for key, ids in list(users.items()):
            prev = PREVIOUS_ACCOUNTS.get(key)
            if prev and isinstance(ids, dict) and "name" not in ids \
                    and (ids.get("uid"), ids.get("gid")) == (prev[1], prev[2]):
                del users[key]
                changes.append(f"service account {key} ({prev[1]}:{prev[2]}): moves to this release's fabric-* account")
        if not users:
            del data["service_users"]
    if data.get("webui_admin_role") == OLD_ADMIN_ROLE:
        data["webui_admin_role"] = ADMIN_ROLE
        changes.append(f"the web console's admin role: {OLD_ADMIN_ROLE} is now {ADMIN_ROLE} (2.1.6.33)")
    return changes
