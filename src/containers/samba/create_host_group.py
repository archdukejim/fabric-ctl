from samba.dsdb import GTYPE_SECURITY_GLOBAL_GROUP

from host_groups import HOST_GROUP_MARK, host_group_name
import paths


def create_host_group(samdb, lp, site, name):
    """Purpose: a new host group (manual 1.6.11.7, 1.6.13.3): a security group `hosts-<name>` in the domain's
             OU=groups, marked as fabric's, for machines to be put in. The name is checked by fabric first.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: host groups are the
             domain's); name — the short name.
    Returns: {"name": the AD name}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (or a constraint violation: the name is taken in the domain),
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "create_host_group")."""
    full = host_group_name(name)
    samdb.newgroup(full, groupou=paths.relative(samdb, paths.folder_dn(samdb, "groups")),
                   grouptype=GTYPE_SECURITY_GLOBAL_GROUP, description=HOST_GROUP_MARK)
    return {"name": full}
