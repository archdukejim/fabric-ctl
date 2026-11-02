"""Print this DC's highest committed USN (manual 1.10.4.26, decision 2.1.10.24): the plan poll's cheap first step.
    docker exec samba python3 /fabric/read_usn.py
An anonymous read of the root DSE over loopback LDAP: no account, no secret. Prints one JSON object {"usn": int}, or
{"error": message} and exits 1."""
import json
import sys

import ldb
from samba import Ldb
from samba.credentials import Credentials
from samba.param import LoadParm

CONF = "/data/etc/smb.conf"


def read_usn(conf=CONF):
    """Purpose: the DC's highestCommittedUSN, which every change written on it or replicated to it raises.
    Inputs:  conf — str, the DC's smb.conf.
    Returns: int.
    Fails:   ldb.LdbError when the DC does not answer on loopback; KeyError, ValueError for a root DSE without it.
    Feeds:   this script's main (fabriclib/ipam/options/read_usn)."""
    lp = LoadParm()
    lp.load(conf)
    creds = Credentials()
    creds.guess(lp)
    creds.set_anonymous()
    db = Ldb(url="ldap://127.0.0.1", credentials=creds, lp=lp)
    res = db.search(base="", scope=ldb.SCOPE_BASE, attrs=["highestCommittedUSN"])
    return int(str(res[0]["highestCommittedUSN"][0]))


if __name__ == "__main__":
    try:
        print(json.dumps({"usn": read_usn()}))
    except Exception as e:                  # the caller reports it; the DC keeps running
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(1)
