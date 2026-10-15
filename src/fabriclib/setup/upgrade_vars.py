from fabriclib.deploy.keep_old_install import keep_old_install
from fabriclib.rbac.permissions import ADMIN_ROLE, OLD_ADMIN_ROLE
from fabriclib.setup.common.previous_accounts import PREVIOUS_ACCOUNTS


def upgrade_vars(data, pinned, provisioned):
    """Purpose: adjust an existing install's vars before a newer fabric re-renders them, so an upgrade never
             changes a running image, and gets this release's service accounts.
    Inputs:  data — the existing vars dict (modified in place); pinned — collection of image_* keys the admin
             set explicitly (left alone); provisioned — bool, this host's domain exists (keep_old_install).
    Returns: list of change descriptions (str), one per image_* key dropped and one per service account moved.
             Keys pinned by digest ("@sha256:") are kept; unpinned refs and local build names not in `pinned` are
             deleted, so the release's validated, digest-pinned default applies. service_users entries that are
             exactly a previous release's default (PREVIOUS_ACCOUNTS: same uid and gid, no name) are deleted, so
             the fabric-* account in the 600-649 band applies (the accounts step moves the files); entries the
             admin changed are kept. The console's admin role named fabric-admin (before 0.6.4) becomes
             fabric-console-admin: that name is now the first admin's (2.1.6.33); Keycloak and OpenBao follow at
             their steps, members kept. 0.7.0: resolver_mem_limit left at 0.8.0-rc's 384m default drops to the
             release's (128m); a DNS filter group's own lists are taken out and named (the lists are the site's).
             certs.<domain> is gone (0.7.0, 1.5.1.5): cname_certs and hostname_certs are deleted, and so is the main
             zone's CNAME to this host under that label if an older vars file holds it.
             What an install from before 0.7.0 keeps (keep_old_install: its DC's name).
    Fails:   never — dict operations only.
    Feeds:   collect_vars (logs each change).
    Notes:   `fabricctl images update` is what changes images (design 2.1.14.3)."""
    changes = keep_old_install(data, provisioned)
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
    # 0.7.0: the lists left the resolver for AdGuard Home (2.1.12.6): its old default limit goes, groups lose theirs
    if str(data.get("resolver_mem_limit") or "").lower() == "384m":
        del data["resolver_mem_limit"]
        changes.append("resolver_mem_limit: 384m -> this release's 128m (the lists are AdGuard Home's, 1.12.3.9)")
    for g in data.get("dns_filter_groups") or []:
        if isinstance(g, dict) and "lists" in g:
            gone = [str((i or {}).get("name") or (i or {}).get("url")) for i in g.pop("lists") or []
                    if isinstance(i, dict)]
            if gone:
                changes.append(f"DNS filter group {g.get('name')}: its own lists are not moved, the lists are the "
                               f"site's from 0.7.0 (1.12.3.11): {', '.join(gone)}")
    if data.get("webui_admin_role") == OLD_ADMIN_ROLE:
        data["webui_admin_role"] = ADMIN_ROLE
        changes.append(f"the web console's admin role: {OLD_ADMIN_ROLE} is now {ADMIN_ROLE} (2.1.6.33)")
    label = data.pop("cname_certs", None) or "certs"
    if data.pop("hostname_certs", None) is not None or label != "certs":
        changes.append("certs.<domain> is gone: the CA is at info.<domain>/certs/ (1.5.1.5)")
    dns = data.get("dns")
    zone = dns.get("dynamic_zone_var") if isinstance(dns, dict) else None
    if isinstance(zone, dict) and isinstance(zone.get("CNAME"), list):
        keep = [r for r in zone["CNAME"] if not (isinstance(r, dict) and r.get("name") == label
                                                 and r.get("canonical") == data.get("hostname"))]
        if len(keep) != len(zone["CNAME"]):
            zone["CNAME"] = keep
            changes.append(f"DNS: the CNAME {label} (certs.<domain>) removed (1.5.1.5)")
    return changes
