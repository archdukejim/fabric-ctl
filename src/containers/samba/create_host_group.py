from samba.dsdb import GTYPE_SECURITY_GLOBAL_GROUP

from host_groups import HOST_GROUP_MARK, host_group_name
from paths import relative, site_dn


def create_host_group(samdb, lp, site, name):
    """Purpose: a new host group of the site (manual 1.6.11.7): a security group `<site>-hosts-<name>` in its
             OU=groups, marked as fabric's, for machines to be put in. The name is checked by fabric first.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the short name.
    Returns: {"name": the AD name}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (or a constraint violation: the name is taken in the domain),
             ERR_INSUFFICIENT_ACCESS_RIGHTS; LookupError (no such site).
    Feeds:   directory_ops (op "create_host_group")."""
    full = host_group_name(site, name)
    samdb.newgroup(full, groupou=relative(samdb, f"OU=groups,{site_dn(samdb, site)}"),
                   grouptype=GTYPE_SECURITY_GLOBAL_GROUP, description=HOST_GROUP_MARK)
    return {"name": full}
