import ldb

COST = "100"
INTERVAL = "15"                  # minutes; changes are also notified at once (options: USE_NOTIFY)
USE_NOTIFY = "1"


def ensure_site_link(samdb, site, parent):
    """Purpose: the AD site link between a site and its parent (manual 1.9.8.5, S8.3): cost 100, every 15 minutes and
             on change notification, so AD's KCC builds replication both ways between their DCs; the link to an
             earlier parent removed (a site that moved, 2.1.6.20); this site's link that lost a race removed: the parent
             and the site each make it when a site moves here, each at its own DC, and AD renames one with a
             `CNF:` suffix when they meet (2.3.1.45).
    Inputs:  samdb — SamDB (as the system); site — the site; parent — its parent site.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (e.g. either AD site missing: ensure_ad_site makes them).
    Feeds:   converge (state parent)."""
    sites = f"CN=Sites,{samdb.get_config_basedn()}"
    ip = f"CN=IP,CN=Inter-Site Transports,{sites}"
    dn = f"CN={parent}-{site},{ip}"
    removed = []
    # a link fabric made to an earlier parent (CN=<other>-<site>, naming both AD sites) goes: the site moved (2.1.6.20)
    for link in samdb.search(base=ip, scope=ldb.SCOPE_ONELEVEL, expression="(objectClass=siteLink)",
                             attrs=["cn", "siteList"]):
        name = str(link["cn"][0])
        if "\nCNF:" in name and name.split("\nCNF:")[0].endswith(f"-{site}"):
            samdb.delete(link.dn)
            removed.append(f"site link {name.split(chr(10))[0]}'s duplicate, from a race, removed")
            continue
        other = name[:-len(site) - 1] if name.endswith(f"-{site}") else ""
        listed = {str(x).lower() for x in link.get("siteList", [])}
        if other and other != parent and {f"cn={other},{sites}".lower(), f"cn={site},{sites}".lower()} <= listed:
            samdb.delete(str(link.dn))
            removed.append(f"site link {name} removed")
    want = {"siteList": sorted([f"CN={parent},{sites}", f"CN={site},{sites}"]), "cost": [COST],
            "replInterval": [INTERVAL], "options": [USE_NOTIFY]}
    try:
        found = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=list(want))
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        found = []
    if not found:
        samdb.add({"dn": dn, "objectClass": "siteLink", **want})
        return removed + [f"site link {parent}-{site} created"]
    msg = ldb.Message(found[0].dn)
    for attr, val in want.items():
        if sorted(str(x).lower() for x in found[0].get(attr, [])) != sorted(x.lower() for x in val):
            msg[attr] = ldb.MessageElement(val, ldb.FLAG_MOD_REPLACE, attr)
    if len(msg) == 0:
        return removed
    samdb.modify(msg)
    return removed + [f"site link {parent}-{site} changed"]
