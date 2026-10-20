import ldb

from find_person import find_person

# the request's names -> AD's standard attributes (fabriclib/domain/person_fields.py checks the values, 2.1.6.93)
FIELDS = {"first": "givenName", "last": "sn", "name": "displayName", "email": "mail", "phone": "telephoneNumber",
          "mobile": "mobile", "title": "title", "department": "department", "company": "company",
          "office": "physicalDeliveryOfficeName", "city": "l", "state": "st", "country": "c", "manager": "manager",
          "employee_id": "employeeID"}


def _record(samdb, dn):
    """Purpose: a person's fields as they are now, the manager by user name.
    Inputs:  samdb — SamDB; dn — the person's DN.
    Returns: {field: str} ("" for one not set).
    Fails:   ldb.LdbError from the search.
    Feeds:   edit_person."""
    now = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=list(FIELDS.values()))[0]
    out = {field: str(now.get(attr, [""])[0]) for field, attr in FIELDS.items()}
    if out["manager"]:
        try:
            found = samdb.search(base=out["manager"], scope=ldb.SCOPE_BASE, attrs=["sAMAccountName"])
            out["manager"] = str(found[0]["sAMAccountName"][0])
        except ldb.LdbError:
            out["manager"] = ""                 # a manager since removed: AD drops the link
    return out


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
    have = _record(samdb, p.dn)
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
    now = _record(samdb, p.dn)
    return {"uid": uid, "name": now["name"], "email": now["email"], "changed": changed, "person": now}
