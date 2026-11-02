from samba.dsdb import GTYPE_SECURITY_GLOBAL_GROUP

import paths
from alloc_id import alloc_id
from may_hold import may_hold

MARK = "an admin's group (manual 1.6.12.5)"


def create_group(samdb, lp, site, name, description="", dc="", ou=""):
    """Purpose: an admin's own group (manual 1.6.12.5, Create group): a security group in OU=groups with a gid from the
             DC's group range (so Linux machines see it, 1.6.5.26). The name is checked by fabric first (fabric's names,
             1.2.13); AD refuses one any account or group of the domain already has.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: groups are the
             domain's); name — the group's name; description — text or ""; dc — the DC asking (its id range); ou —
             an OU's path (Create in..., 2.1.6.101; where may_hold lets a group be), or "" for OU=groups.
    Returns: {"name", "gid"}.
    Fails:   ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (or a constraint violation: the name is taken in the domain),
             ERR_INSUFFICIENT_ACCESS_RIGHTS; ValueError from alloc_id (the range full) or may_hold (that OU).
    Feeds:   directory_ops (op "create_group")."""
    where = may_hold(samdb, "group", ou) if ou else paths.folder_dn(samdb, "groups")
    gid = alloc_id(samdb, dc, "group")
    samdb.newgroup(name, groupou=paths.relative(samdb, where),
                   grouptype=GTYPE_SECURITY_GLOBAL_GROUP, description=description or MARK, gidnumber=str(gid))
    return {"name": name, "gid": gid}
