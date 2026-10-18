"""The names of the domain's domain controllers and of every other computer account (manual 1.6.5.23), read from this
DC's own database, so a parent gives a joining site's DC the lowest name not in use before the join is prepared
(2.1.6.65).
    docker exec samba python3 /fabric/read_dc_names.py
Prints one JSON object: {"dcs": [name, …], "computers": [name, …]} (lower case, without the trailing $)."""
import json
import sys

import ldb

from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"
SERVER_TRUST, PARTIAL_SECRETS = 0x2000, 0x4000000     # userAccountControl: a DC, a read-only DC


def read_dc_names():
    """Purpose: the computer names the domain holds, its DCs apart.
    Inputs:  none (the DC's own database, as the system).
    Returns: {"dcs": sorted names of the writable and read-only DCs, "computers": sorted names of every computer
             account, DCs included}.
    Fails:   ldb.LdbError from the search.
    Feeds:   this script's main."""
    samdb, _ = open_samdb(CONF)
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=computer)",
                       attrs=["sAMAccountName", "userAccountControl"])
    dcs, computers = set(), set()
    for r in res:
        name = str(r["sAMAccountName"][0]).rstrip("$").lower()
        computers.add(name)
        if int(str(r.get("userAccountControl", [0])[0])) & (SERVER_TRUST | PARTIAL_SECRETS):
            dcs.add(name)
    return {"dcs": sorted(dcs), "computers": sorted(computers)}


if __name__ == "__main__":
    try:
        print(json.dumps(read_dc_names()))
    except Exception as e:                  # reported by the caller; the DC keeps running
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
