"""Every DC's record the domain holds (manual 1.6.13.2, 2.1.6.79): each DC's name, its site and its id range, read
from this DC's own database, so a parent sees the sites and DCs every other DC made, and a site that moves under it
(2.1.6.20) already exists.
    docker exec samba python3 /fabric/read_sites.py
Prints one JSON object: {"dcs": [{"dc", "site", "id_range"}, …]}."""
import json
import sys

import ldb

from open_samdb import open_samdb
import paths

CONF = "/data/etc/smb.conf"


def read_sites():
    """Purpose: the DCs' records in the domain, each with its site.
    Inputs:  none (the DC's own database, as the system).
    Returns: {"dcs": [{"dc", "site", "id_range" ("first-last")}]}, by name; [] before the domain has converged.
    Fails:   ldb.LdbError from the search (but a missing CN=dcs: none yet).
    Feeds:   this script's main."""
    samdb, _ = open_samdb(CONF)
    try:
        res = samdb.search(base=f"CN=dcs,{paths.fabric_dn(samdb)}", scope=ldb.SCOPE_ONELEVEL,
                           expression="(objectClass=fabricDcInfo)", attrs=["cn", "fabricSite", "fabricIdRange"])
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        res = []
    return {"dcs": sorted(({"dc": str(r["cn"][0]), "site": str(r.get("fabricSite", [""])[0]),
                            "id_range": str(r.get("fabricIdRange", [""])[0])} for r in res),
                          key=lambda d: d["dc"])}


if __name__ == "__main__":
    try:
        print(json.dumps(read_sites()))
    except Exception as e:                  # reported by the caller; the DC keeps running
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
