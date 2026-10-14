import ldb

import paths
from read_site_dcs import read_site_dcs
from set_ssh_cas import KEYWORD, RDN


def read_ssh_cas(samdb, lp, site):
    """Purpose: the organisation's SSH CAs (decision 2.1.7.14, manual 1.6.11.9.16): every site's `CN=fabric-ssh-cas`
             object. Each object's site is the site OU it sits directly in (never what it says about itself), and
             whether that site has a writable DC comes from AD's configuration partition (read_site_dcs).
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm; site — str (the asking site, unused).
    Returns: {"sites": [{"site", "user_ca", "host_ca", "domain", "writable": bool}]}, by site name.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "read_ssh_cas") <- vault/ssh/sign_ssh_hosts."""
    found = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=serviceConnectionPoint)(keywords={KEYWORD}))",
                         attrs=["serviceBindingInformation"])
    dc_types = read_site_dcs(samdb, lp, site)["sites"]
    out = []
    for obj in found:
        dn = str(obj.dn)
        if not dn.lower().startswith(RDN.lower() + ","):
            continue
        parent = dn.split(",", 1)[1]
        owner = parent.split(",", 1)[0]
        if not owner.lower().startswith("ou="):
            continue
        owner = owner[3:]
        try:
            if paths.site_dn(samdb, owner).lower() != parent.lower():
                continue                       # not directly in a site's own OU
        except LookupError:
            continue
        entry = {"site": owner, "user_ca": "", "host_ca": "", "domain": "",
                 "writable": dc_types.get(owner, {}).get("type") == "writable"}
        for value in obj.get("serviceBindingInformation", []):
            kind, _, rest = str(value).partition(" ")
            if kind == "user":
                entry["user_ca"] = rest.strip()
            elif kind == "host":
                entry["host_ca"] = rest.strip()
            elif kind == "domain":
                entry["domain"] = rest.strip().lower()
        out.append(entry)
    return {"sites": sorted(out, key=lambda e: e["site"])}
