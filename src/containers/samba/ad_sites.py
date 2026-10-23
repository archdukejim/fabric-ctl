import ldb


def _cn(dn):
    """Purpose: the first RDN's value of a DN.
    Inputs:  dn — str or ldb.Dn.
    Returns: str.
    Fails:   never.
    Feeds:   ad_sites."""
    return str(dn).split(",", 1)[0].split("=", 1)[-1]


def ad_sites(samdb, lp, site):
    """Purpose: AD's own sites as fabric wrote them (manual 1.6.12.8, 1.9.8.5), read-only: each AD site with its
             domain controllers, its subnets and the site links naming it.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the domain's).
    Returns: {"sites": [{"name", "dcs": [names, lower case], "subnets": [CIDR], "links": [{"name", "sites": [names],
             "cost", "interval"}]}]}, by name.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "ad_sites")."""
    base = f"CN=Sites,{samdb.get_config_basedn()}"
    out = {}
    for m in samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=site)", attrs=["cn"]):
        name = str(m["cn"][0])
        dcs = []
        try:
            dcs = [str(s["cn"][0]).lower() for s in samdb.search(base=f"CN=Servers,{m.dn}", scope=ldb.SCOPE_ONELEVEL,
                                                                  expression="(objectClass=server)", attrs=["cn"])]
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
                raise
        out[name] = {"name": name, "dcs": sorted(dcs), "subnets": [], "links": []}
    for s in samdb.search(base=f"CN=Subnets,{base}", scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=subnet)",
                          attrs=["cn", "siteObject"]):
        owner = _cn(s["siteObject"][0]) if s.get("siteObject") else ""
        if owner in out:
            out[owner]["subnets"].append(str(s["cn"][0]))
    ip = f"CN=IP,CN=Inter-Site Transports,{base}"
    for link in samdb.search(base=ip, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=siteLink)",
                             attrs=["cn", "siteList", "cost", "replInterval"]):
        names = sorted(_cn(x) for x in link.get("siteList", []))
        row = {"name": str(link["cn"][0]), "sites": names, "cost": str(link.get("cost", [""])[0]),
               "interval": str(link.get("replInterval", [""])[0])}
        for n in names:
            if n in out:
                out[n]["links"].append(row)
    for row in out.values():
        row["subnets"].sort()
    return {"sites": [out[n] for n in sorted(out)]}
