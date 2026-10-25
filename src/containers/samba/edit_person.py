import ldb

from find_person import find_person
from person_record import FIELDS, person_record


def edit_person(samdb, lp, site, uid, fields):
    """Purpose: a person's details changed (manual 1.6.12.4, Edit; 2.1.6.93): only the fields given, an empty value
             clearing one; an e-mail address another account holds is refused (fabric keeps them unique, as
             create_person does); the manager is a person in OU=people, by user name, stored as their DN.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name;
             fields — {field: str} of FIELDS, checked by fabriclib (read_person_fields).
    Returns: {"uid", "name", "email", "changed": [the attributes changed], "person": {field: value}}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no such person in OU=people, or the manager is not a person),
             ERR_ENTRY_ALREADY_EXISTS (the address is another's), ERR_INSUFFICIENT_ACCESS_RIGHTS; KeyError for a
             field not in FIELDS.
    Feeds:   directory_ops (op "edit_person")."""
    p = find_person(samdb, uid)
    have = person_record(samdb, p.dn)
    msg, changed = ldb.Message(p.dn), []
    for field, value in fields.items():
        attr = FIELDS[field]
        if have[field] == value:
            continue
        if not value:
            msg[attr] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, attr)
            changed.append(attr)
            continue
        if field == "email":
            taken = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                 expression=f"(&(mail={ldb.binary_encode(value)})"
                                            f"(!(sAMAccountName={ldb.binary_encode(uid)})))")
            if taken:
                raise ldb.LdbError(ldb.ERR_ENTRY_ALREADY_EXISTS, f"the e-mail address {value} is another's")
        if field == "manager":
            value = str(find_person(samdb, value).dn)
        msg[attr] = ldb.MessageElement([value], ldb.FLAG_MOD_REPLACE, attr)
        changed.append(attr)
    if changed:
        samdb.modify(msg)
    now = person_record(samdb, p.dn)
    return {"uid": uid, "name": now["name"], "email": now["email"], "changed": changed, "person": now}
