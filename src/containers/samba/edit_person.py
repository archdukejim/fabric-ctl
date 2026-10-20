import ldb

from find_person import find_person


def edit_person(samdb, lp, site, uid, name=None, email=None):
    """Purpose: a person's display name and e-mail address changed (manual 1.6.12.4, Edit): only what is given; an
             e-mail address another account holds is refused (fabric keeps them unique, as create_person does).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name;
             name — the display name, or None (kept); email — the e-mail address, or None (kept).
    Returns: {"uid", "name", "email", "changed": [the attributes changed]}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such person in OU=people), ERR_ENTRY_ALREADY_EXISTS (the address is
             another's), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "edit_person")."""
    p = find_person(samdb, uid)
    have = samdb.search(base=p.dn, scope=ldb.SCOPE_BASE, attrs=["displayName", "mail"])[0]
    msg, changed = ldb.Message(p.dn), []
    for attr, value in (("displayName", name), ("mail", email)):
        if value is None or str(have.get(attr, [""])[0]) == value:
            continue
        if attr == "mail":
            taken = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                 expression=f"(&(mail={ldb.binary_encode(value)})"
                                            f"(!(sAMAccountName={ldb.binary_encode(uid)})))")
            if taken:
                raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"the e-mail address {value} is another's")
        msg[attr] = ldb.MessageElement([value], ldb.FLAG_MOD_REPLACE, attr)
        changed.append(attr)
    if changed:
        samdb.modify(msg)
    now = samdb.search(base=p.dn, scope=ldb.SCOPE_BASE, attrs=["displayName", "mail"])[0]
    return {"uid": uid, "name": str(now.get("displayName", [""])[0]), "email": str(now.get("mail", [""])[0]),
            "changed": changed}
