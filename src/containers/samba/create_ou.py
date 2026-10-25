import ldb

from ou_paths import ADMIN_ROOTS, FABRIC_NAMES, NAME_RE, exists, is_admin_ou, ou_dn

MARK = "an admin's folder (manual 1.6.12.7): OUs grant nothing"


def create_ou(samdb, lp, site, parent, name):
    """Purpose: an admin's own OU (manual 1.6.12.7, Create OU), under OU=people, OU=service-accounts, OU=groups, a
             machine type's OU, or an admin's own OU below one of those; never under fabric's other folders (OU=fabric,
             OU=machines itself, ...) and never named as one of fabric's folders.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); parent — the parent's
             path ("people", "machines/servers/web"); name — the new OU's name.
    Returns: {"path", "dn"}.
    Fails:   ValueError: a bad name, one of fabric's names, a parent where an admin may not add a folder, no such
             parent; ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (the name taken there), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "create_ou")."""
    if not NAME_RE.match(str(name or "")):
        raise ValueError("an OU's name: 1-63 letters, digits, space, _ . -, starting with a letter or digit")
    if name.lower() in FABRIC_NAMES:
        raise ValueError(f"{name} is one of fabric's folders' names (manual 1.6.13.2): choose another")
    pdn = ou_dn(samdb, parent)
    if not (str(parent).strip("/") in ADMIN_ROOTS or is_admin_ou(samdb, pdn)):
        raise ValueError(f"{parent} takes no admin's folders: add them under {', '.join(ADMIN_ROOTS)} "
                         "(manual 1.6.12.7)")
    if not exists(samdb, pdn):
        raise ValueError(f"no OU {parent}")
    dn = f"OU={name},{pdn}"
    if exists(samdb, dn):
        raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"an OU {name} is already in {parent}")
    samdb.add({"dn": dn, "objectClass": "organizationalUnit", "description": MARK})
    return {"path": f"{str(parent).strip('/')}/{name}", "dn": dn}
