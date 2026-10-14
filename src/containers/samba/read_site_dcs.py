import ldb

SERVER_TRUST_ACCOUNT = 0x2000           # a writable domain controller's account (userAccountControl)
PARTIAL_SECRETS_ACCOUNT = 0x04000000    # a read-only domain controller's account


def read_site_dcs(samdb, lp, site, sites=None):
    """Purpose: each AD site's domain controllers and whether each is read-only (decisions 2.1.9.23, 2.1.7.14; manual
             1.9.8.22.1, 1.6.11.9.16), from AD's configuration partition (the servers of `CN=<site>,CN=Sites`, which
             no site's agent can write) and each server's computer account (`userAccountControl`:
             PARTIAL_SECRETS_ACCOUNT for a read-only DC, SERVER_TRUST_ACCOUNT for a writable one) — never from
             anything a site writes about itself.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str (the asking site, unused);
             sites — list of AD site names to report, or None for all.
    Returns: {"sites": {name: {"dcs": [{"name", "read_only": bool}], "type": "writable" | "rodc" | "none"}}}: "writable"
             when at least one of its DCs is writable, "rodc" when it has only read-only ones, "none" without a DC.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "read_site_dcs") <- federation/request_dc_type, federation/change_dc_type,
             read_ssh_cas."""
    base = f"CN=Sites,{samdb.get_config_basedn()}"
    out = {}
    for s in samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=site)", attrs=["cn"]):
        name = str(s["cn"][0])
        if sites is not None and name not in sites:
            continue
        dcs = []
        for srv in samdb.search(base=str(s.dn), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=server)",
                                attrs=["cn", "serverReference"]):
            if "serverReference" not in srv:
                continue
            try:
                acct = samdb.search(base=str(srv["serverReference"][0]), scope=ldb.SCOPE_BASE,
                                    attrs=["userAccountControl"])[0]
            except ldb.LdbError:
                continue                       # a server object left behind by a DC that is gone
            uac = int(str(acct.get("userAccountControl", ["0"])[0]))
            if uac & (SERVER_TRUST_ACCOUNT | PARTIAL_SECRETS_ACCOUNT):
                dcs.append({"name": str(srv["cn"][0]).lower(), "read_only": bool(uac & PARTIAL_SECRETS_ACCOUNT)})
        kind = "none" if not dcs else ("writable" if any(not d["read_only"] for d in dcs) else "rodc")
        out[name] = {"dcs": sorted(dcs, key=lambda d: d["name"]), "type": kind}
    return {"sites": out}
