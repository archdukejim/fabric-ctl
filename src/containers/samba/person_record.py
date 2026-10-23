import ldb

# the request's names -> AD's standard attributes (fabriclib/domain/person_fields.py checks the values, 2.1.6.93)
FIELDS = {"first": "givenName", "last": "sn", "name": "displayName", "email": "mail", "phone": "telephoneNumber",
          "mobile": "mobile", "title": "title", "department": "department", "company": "company",
          "office": "physicalDeliveryOfficeName", "city": "l", "state": "st", "country": "c", "manager": "manager",
          "employee_id": "employeeID"}


def person_record(samdb, dn):
    """Purpose: a person's fields as they are now, the manager by user name.
    Inputs:  samdb — SamDB; dn — the person's DN.
    Returns: {field: str} ("" for one not set).
    Fails:   ldb.LdbError from the search.
    Feeds:   edit_person, get_person."""
    now = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=list(FIELDS.values()))[0]
    out = {field: str(now.get(attr, [""])[0]) for field, attr in FIELDS.items()}
    if out["manager"]:
        try:
            found = samdb.search(base=out["manager"], scope=ldb.SCOPE_BASE, attrs=["sAMAccountName"])
            out["manager"] = str(found[0]["sAMAccountName"][0])
        except ldb.LdbError:
            out["manager"] = ""                 # a manager since removed: AD drops the link
    return out
