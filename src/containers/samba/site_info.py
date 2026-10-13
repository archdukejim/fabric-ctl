import ldb

import paths


def site_info(samdb, lp, site):
    """Purpose: what the directory knows of a site: its OU, its id block and how far it is used.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused: every operation takes it); site — str.
    Returns: dict {"dn", "id_range" "first-last", "id_marks" {kind: next} (its fixed ranges' marks, 2.1.6.46)}.
    Fails:   ldb.LdbError (no such OU, or not readable).
    Feeds:   directory_ops (op "site_info")."""
    dn = paths.site_dn(samdb, site)
    res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricIdRange", "fabricIdMark"])[0]
    marks = {}
    for m in res.get("fabricIdMark", []):
        kind, value = str(m).split("=", 1)
        marks[kind] = max(int(value), marks.get(kind, 0))
    return {"dn": dn, "id_range": str(res["fabricIdRange"][0]), "id_marks": marks}
