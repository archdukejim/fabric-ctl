import ldb

# AD's domain functional levels (msDS-Behavior-Version) by their Windows Server names
LEVELS = {0: "2000", 1: "2003 interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}
DC_GROUPS = {516: True, 521: False}               # Domain Controllers (writable), Read-only Domain Controllers


def domain_facts(samdb, lp, site):
    """Purpose: the domain at a glance for the Directory's Overview (manual 1.6.12.3): its functional level and its
             domain controllers, writable or read-only.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the domain's).
    Returns: {"level": "2008 R2" (or the raw number for one not in LEVELS), "dcs": [{"name", "dns", "writable"}]
             sorted by name}.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "domain_facts")."""
    base = str(samdb.domain_dn())
    top = samdb.search(base=base, scope=ldb.SCOPE_BASE, attrs=["msDS-Behavior-Version"])[0]
    raw = int(str(top.get("msDS-Behavior-Version", ["0"])[0]))
    dcs = []
    for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE,
                          expression="(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))",
                          attrs=["sAMAccountName", "dNSHostName", "primaryGroupID"]):
        dcs.append({"name": str(m["sAMAccountName"][0]).rstrip("$").lower(),
                    "dns": str(m.get("dNSHostName", [""])[0]),
                    "writable": DC_GROUPS.get(int(str(m["primaryGroupID"][0])), True)})
    return {"level": LEVELS.get(raw, str(raw)), "dcs": sorted(dcs, key=lambda d: d["name"])}
