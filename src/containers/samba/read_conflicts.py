"""The objects AD renamed `CNF:` after the same name was made on two DCs while they were apart (manual 1.9.8.5, Q12),
read from this DC's own database, in every partition: the `ldbsearch` this replaces saw the domain's alone, and so never
showed a site link lost to a race, in Configuration (2.3.1.45).
    docker exec samba python3 /fabric/read_conflicts.py
Prints one JSON object: {"conflicts": [DN, ...]}."""
import json
import sys

import ldb

from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"


def read_conflicts():
    """Purpose: every object whose name says it lost a conflict.
    Inputs:  none (the DC's own database, as the system).
    Returns: {"conflicts": [DN]}.
    Fails:   ldb.LdbError from the searches.
    Feeds:   this script's main; directory_op's held process."""
    samdb, _ = open_samdb(CONF)
    found = []
    for base in samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=["namingContexts"])[0]["namingContexts"]:
        found += [str(r.dn) for r in samdb.search(base=base.decode(), scope=ldb.SCOPE_SUBTREE,
                                                  expression="(name=*CNF:*)", attrs=["dn"])]
    return {"conflicts": found}


if __name__ == "__main__":
    try:
        print(json.dumps(read_conflicts()))
    except Exception as e:                  # reported by the caller; the DC keeps running
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
