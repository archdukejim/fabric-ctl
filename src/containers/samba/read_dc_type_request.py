import ldb

import paths
from set_dc_type_request import FIELDS, RDN


def read_dc_type_request(samdb, lp, site, target=None):
    """Purpose: the pending request to change a site's DC type, as set_dc_type_request keeps it (decision 2.1.9.23,
             manual 1.9.8.20.2).
    Inputs:  samdb — SamDB; lp — unused; site — the asking site; target — the site whose request to read (default:
             the asking site).
    Returns: {"site", "request": {"to", "by", "actor", "at", "id"} or None}.
    Fails:   LookupError when the site is not in the domain; ldb.LdbError from the search.
    Feeds:   directory_ops (op "read_dc_type_request") <- federation/change_dc_type, federation/accept_dc_type,
             federation/federation_overview."""
    target = target or site
    dn = f"{RDN},{paths.site_dn(samdb, target)}"
    try:
        obj = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["keywords"])[0]
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        return {"site": target, "request": None}
    request = {}
    for k in obj.get("keywords", []):
        field, sep, value = str(k).partition("=")
        if sep and field in FIELDS:
            request[field] = value
    return {"site": target, "request": request if all(f in request for f in FIELDS) else None}
