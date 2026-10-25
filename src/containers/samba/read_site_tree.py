"""Every site's record the domain holds with its place in the federation (decision 2.1.8.30, manual 1.8.6.12): its
parent and its console's address, read from this DC's own database, so every site sees every other's.
    docker exec samba python3 /fabric/read_site_tree.py
Prints one JSON object: {"sites": [{"site", "parent", "console"}, ...]}."""
import json
import sys

import ldb

from open_samdb import open_samdb
import paths

CONF = "/data/etc/smb.conf"


def read_site_tree():
    """Purpose: the sites' records in CN=sites,CN=fabric,CN=System, each with its parent and console's address.
    Inputs:  none (the DC's own database, as the system).
    Returns: {"sites": [{"site", "parent" ("" for none), "console" ("" when not known)}]}, by name; [] before the
             domain has converged.
    Fails:   ldb.LdbError from the search (but a missing CN=sites: none yet).
    Feeds:   this script's main."""
    samdb, _ = open_samdb(CONF)
    try:
        res = samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_ONELEVEL,
                           expression="(objectClass=fabricSiteRecord)",
                           attrs=["cn", "fabricParentSite", "fabricConsoleUrl"])
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        res = []
    return {"sites": sorted(({"site": str(r["cn"][0]), "parent": str(r.get("fabricParentSite", [""])[0]),
                              "console": str(r.get("fabricConsoleUrl", [""])[0])} for r in res),
                            key=lambda s: s["site"])}


if __name__ == "__main__":
    try:
        print(json.dumps(read_site_tree()))
    except Exception as e:                  # reported by the caller; the DC keeps running
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
