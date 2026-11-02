import ldb

from ensure_ou_rights import ensure_ou_rights
from ou_paths import FABRIC_NAMES, NAME_RE, exists, ou_dn, place_ok

MARK = "an admin's folder (manual 1.6.12.7): OUs grant nothing"


def create_ou(samdb, lp, site, parent, name, dc=""):
    """Purpose: an admin's own OU (manual 1.6.12.7, Create OU), anywhere since 0.9.1 (1.8.8.5, 2.1.6.101): at the
             domain's root, under OU=people, OU=service-accounts, OU=groups, OU=machines or a machine type's OU, or
             under an admin's own OU wherever it is; never inside fabric's closed folders or AD's Domain Controllers
             (ou_paths.place_ok) and never named as one of fabric's folders. One at the root gets the Directory
             Administrators' and fabric's rights at once, written by the agent as its owner (ensure_ou_rights,
             2.1.6.102); one below another OU inherits them.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); parent — the parent's
             path ("people", "machines/servers/web"; "" for the domain's root); name — the new OU's name.
    Returns: {"path", "dn"}.
    Fails:   ValueError: a bad name, one of fabric's names, a parent where an admin may not add a folder, no such
             parent; ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (the name taken there), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "create_ou")."""
    if not NAME_RE.match(str(name or "")):
        raise ValueError("an OU's name: 1-63 letters, digits, space, _ . -, starting with a letter or digit")
    if name.lower() in FABRIC_NAMES:
        raise ValueError(f"{name} is one of fabric's folders' names (manual 1.6.13.2): choose another")
    top = not str(parent or "").strip("/")
    pdn = str(samdb.domain_dn()) if top else ou_dn(samdb, parent)
    if not place_ok(samdb, pdn):
        raise ValueError(f"{parent} is one of fabric's closed folders (or AD's Domain Controllers): an admin's OU goes "
                         "anywhere else (manual 1.6.12.7)")
    if not exists(samdb, pdn):
        raise ValueError(f"no OU {parent}")
    dn = f"OU={name},{pdn}"
    if exists(samdb, dn):
        raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"an OU {name} is already in {parent}")
    samdb.add({"dn": dn, "objectClass": "organizationalUnit", "description": MARK})
    if top and dc:
        ensure_ou_rights(samdb, dc, only=dn)
    return {"path": name if top else f"{str(parent).strip('/')}/{name}", "dn": dn}
