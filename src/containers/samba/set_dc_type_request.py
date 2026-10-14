import ldb

import paths

RDN = "CN=fabric-dc-type-request"
KEYWORD = "fabric-dc-type-request"
FIELDS = ("to", "by", "actor", "at", "id")


def set_dc_type_request(samdb, lp, site, target, request=None):
    """Purpose: the request to change a site's DC type, kept in that site's own OU (decision 2.1.9.23, manual
             1.9.8.22.1): a serviceConnectionPoint `CN=fabric-dc-type-request` whose keywords are
             `fabric-dc-type-request` and `<field>=<value>` for each of FIELDS; None removes it. Written by a site
             above (its agent's inherited rights reach the target's OU; a sibling's or a site below's are refused by
             AD) or, to remove it, by the site itself. Idempotent.
    Inputs:  samdb — SamDB (as the asking site's agent); lp — unused; site — the asking site; target — the site whose
             request it is; request — {"to", "by", "actor", "at", "id"} (str values without "="-less garbage), or None.
    Returns: {"changed": bool, "dn"}.
    Fails:   ValueError (kind "invalid"): a request without one of FIELDS, a value with a newline, or a "to" that is
             not writable or rodc; LookupError when target is not a site of the domain; ldb.LdbError from a change AD
             refuses (insufficient rights: "refused").
    Feeds:   directory_ops (op "set_dc_type_request") <- federation/request_dc_type, federation/change_dc_type."""
    dn = f"{RDN},{paths.site_dn(samdb, target)}"
    try:
        samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["keywords"])
        exists = True
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        exists = False
    if request is None:
        if exists:
            samdb.delete(dn)
        return {"changed": exists, "dn": dn}
    if any(not str(request.get(f) or "") or "\n" in str(request.get(f)) for f in FIELDS):
        raise ValueError("a DC type request needs " + ", ".join(FIELDS))
    if request["to"] not in ("writable", "rodc"):
        raise ValueError("a DC type is writable or rodc")
    keywords = [KEYWORD] + [f"{f}={request[f]}" for f in FIELDS]
    if exists:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "keywords": keywords}, ldb.FLAG_MOD_REPLACE))
    else:
        samdb.add({"dn": dn, "objectClass": "serviceConnectionPoint", "keywords": keywords})
    return {"changed": True, "dn": dn}
