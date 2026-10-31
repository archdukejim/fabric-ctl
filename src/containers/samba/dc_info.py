import ldb

import paths


def dc_info(samdb, lp, site, dc=""):
    """Purpose: what the directory knows of a DC (2.1.6.79): its record, its id range, how far each of the range's
             fixed parts is used (2.1.6.46) and its site.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused: every operation takes it); site — str
             (unused); dc — the DC's name (the request's).
    Returns: dict {"dn", "dc", "site", "id_range" "first-last", "id_marks" {kind: next}}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT (no record: the DC has not converged), or not readable.
    Feeds:   directory_ops (op "dc_info")."""
    dn = paths.dc_record_dn(samdb, dc)
    res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricIdRange", "fabricIdMark", "fabricSite"])[0]
    marks = {}
    for m in res.get("fabricIdMark", []):
        kind, value = str(m).split("=", 1)
        marks[kind] = max(int(value), marks.get(kind, 0))
    return {"dn": dn, "dc": dc, "site": str(res.get("fabricSite", [""])[0]),
            "id_range": str(res.get("fabricIdRange", [""])[0]), "id_marks": marks}
