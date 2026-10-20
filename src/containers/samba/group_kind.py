import ldb

import paths
from group_names import DC_HOSTS, DIRECTORY_ADMINS, DOMAIN_GROUPS

FILLED = ("machines-",)                     # filled by fabric: a machine's type (1.6.13.3)
FABRIC_PREFIXES = ("site-", "rodc-cache-")  # fabric's, made per site and per read-only DC


def group_kind(samdb, name, bundles=()):
    """Purpose: what a group is, for what may be done to it (manual 1.6.12.2, 1.6.12.5): AD's own (outside OU=groups,
             left as AD has it), one of the grants' computed groups (OU=fabric: written only by fabric), one of the
             tiers' (`directory-admins`: the Enterprise Admin's to change, 2.1.6.68; `dc-hosts`: fabric's), one fabric
             fills (`machines-*`: a computer's type), a machine group (`hosts-*`, its own page, 1.6.11.7), one of
             fabric's own (the domain's groups, `site-*`, `rodc-cache-*`, a group carrying a role bundle), or an
             admin's own.
    Inputs:  samdb — SamDB; name — the group's sAMAccountName; bundles — the names of the groups carrying a fabric
             role bundle (the settings' ldap_groups).
    Returns: {"dn": str, "name": str (as AD has it), "kind": "ad"|"computed"|"tier"|"filled"|"host-group"|"fabric"|
             "bundle"|"own"}.
    Fails:   ValueError "no group <name> in the domain"; ldb.LdbError from the search.
    Feeds:   authorize_action, group_scope, remove_group, set_group_managers, create_group."""
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["sAMAccountName"],
                         expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    if not found:
        raise ValueError(f"no group {name} in the domain")
    dn, real = str(found[0].dn), str(found[0]["sAMAccountName"][0])
    low, lname = dn.lower(), real.lower()
    if not low.endswith("," + paths.folder_dn(samdb, "groups").lower()):
        kind = "ad"
    elif low.endswith("," + paths.computed_groups_dn(samdb).lower()):
        kind = "computed"
    elif lname in (DIRECTORY_ADMINS, DC_HOSTS):
        kind = "tier"
    elif lname.startswith(FILLED):
        kind = "filled"
    elif lname.startswith("hosts-"):
        kind = "host-group"
    elif lname in DOMAIN_GROUPS or lname.startswith(FABRIC_PREFIXES):
        kind = "fabric"
    elif lname in {b.lower() for b in bundles}:
        kind = "bundle"
    else:
        kind = "own"
    return {"dn": dn, "name": real, "kind": kind}
