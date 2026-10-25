import ldb

from ou_paths import FABRIC_NAMES, NAME_RE, exists, is_admin_ou, ou_dn


def rename_ou(samdb, lp, site, path, name):
    """Purpose: an admin's own OU renamed in place (manual 1.6.12.7, Rename): what it holds moves with it; fabric's
             own OUs are refused.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); path — the OU's path;
             name — its new name.
    Returns: {"path", "dn"} (the new ones).
    Fails:   ValueError: a bad name, one of fabric's names, fabric's own OU, no such OU; ldb.LdbError
             ERR_ENTRY_ALREADY_EXISTS (the name taken beside it), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "rename_ou")."""
    if not NAME_RE.match(str(name or "")):
        raise ValueError("an OU's name: 1-63 letters, digits, space, _ . -, starting with a letter or digit")
    if name.lower() in FABRIC_NAMES:
        raise ValueError(f"{name} is one of fabric's folders' names (manual 1.6.13.2): choose another")
    dn = ou_dn(samdb, path)
    if not is_admin_ou(samdb, dn):
        raise ValueError(f"{path} is one of fabric's folders, or not below one an admin adds to: managed by fabric")
    if not exists(samdb, dn):
        raise ValueError(f"no OU {path}")
    new = f"OU={name},{dn.split(',', 1)[1]}"
    if exists(samdb, new):
        raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"an OU {name} is already beside {path}")
    samdb.rename(dn, new)
    parent = str(path).strip("/").rsplit("/", 1)[0]
    return {"path": f"{parent}/{name}", "dn": new}
