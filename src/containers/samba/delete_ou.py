import ldb

from ou_paths import exists, is_admin_ou, ou_dn


def delete_ou(samdb, lp, site, path):
    """Purpose: an admin's own OU deleted (manual 1.6.12.7, Delete), refused while it holds anything, naming what (the
             first few, and how many); fabric's own OUs refused.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); path — the OU's path.
    Returns: {"path"}.
    Fails:   ValueError: fabric's own OU, no such OU, "<path> is not empty: …"; ldb.LdbError
             ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "delete_ou")."""
    dn = ou_dn(samdb, path)
    if not is_admin_ou(samdb, dn):
        raise ValueError(f"{path} is one of fabric's folders, or not below one an admin adds to: managed by fabric")
    if not exists(samdb, dn):
        raise ValueError(f"no OU {path}")
    held = samdb.search(base=dn, scope=ldb.SCOPE_ONELEVEL, attrs=["name"])
    if held:
        names = sorted(str(m.dn).split(",", 1)[0] for m in held)
        more = f" and {len(names) - 5} more" if len(names) > 5 else ""
        raise ValueError(f"{path} is not empty: it holds {', '.join(names[:5])}{more} (manual 1.6.12.7)")
    samdb.delete(dn)
    return {"path": str(path).strip("/")}
