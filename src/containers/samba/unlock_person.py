import ldb

from find_person import find_person


def unlock_person(samdb, lp, site, uid):
    """Purpose: a person's lockout cleared (manual 1.6.12.4, Unlock; `people:reset` widened, 1.6.12.11): AD's
             `lockoutTime` set to 0, as Windows' "Unlock account" does; their password is kept.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name.
    Returns: {"uid", "changed": bool} (False when they were not locked out).
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such person in OU=people), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "unlock_person")."""
    p = find_person(samdb, uid)
    if int(str(p.get("lockoutTime", idx=0) or 0)) == 0:
        return {"uid": uid, "changed": False}
    msg = ldb.Message(p.dn)
    msg["lockoutTime"] = ldb.MessageElement(["0"], ldb.FLAG_MOD_REPLACE, "lockoutTime")
    samdb.modify(msg)
    return {"uid": uid, "changed": True}
