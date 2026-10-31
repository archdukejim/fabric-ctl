import ldb

from ou_paths import fixed_dns, is_admin_ou, ou_path


def list_ous(samdb, lp, site):
    """Purpose: the tree of the domain's folders (manual 1.6.12.7): every OU, fabric's fixed ones marked, with what
             each holds directly (people, groups, computers, OUs, anything else), as counts. AD's own containers are
             not OUs and are not listed.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused).
    Returns: {"ous": [{"path", "dn", "fabric": bool, "own": bool (an admin's, changeable), "holds": {"people",
             "groups", "computers", "ous", "other"}}]}, by path.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "list_ous")."""
    fixed, out = fixed_dns(samdb), []
    for ou in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                           expression="(objectClass=organizationalUnit)", attrs=["dn"]):
        dn = str(ou.dn)
        if dn.lower().startswith("ou=domain controllers,"):
            continue
        holds = {"people": 0, "groups": 0, "computers": 0, "ous": 0, "other": 0}
        for child in samdb.search(base=dn, scope=ldb.SCOPE_ONELEVEL, attrs=["objectClass"]):
            classes = {str(c).lower() for c in child.get("objectClass", [])}
            key = ("computers" if "computer" in classes else "people" if "user" in classes
                   else "groups" if "group" in classes else "ous" if "organizationalunit" in classes else "other")
            holds[key] += 1
        out.append({"path": ou_path(samdb, dn), "dn": dn, "fabric": dn.lower() in fixed,
                    "own": is_admin_ou(samdb, dn), "holds": holds})
    return {"ous": sorted(out, key=lambda o: o["path"].lower())}
