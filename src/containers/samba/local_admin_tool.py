"""The local-admin switches inside the DC (manual 1.7.1.4.6), run as root on its own database (no credentials, no
network) by fabriclib/localadmin/local_admin_request:
    docker exec -i samba python3 /fabric/local_admin_tool.py < request.json
The request on stdin: {"op": "get"|"set"|"ack", "dc" (the DC whose host is meant), "this_dc", "writable" (bool:
this DC is writable), "writable_dc" (the writable DC to name from a read-only one), for set "ssh" (bool), and for
set and ack "by", "when"}.
Prints one JSON object: {"result": …} or {"error": message} (exit 0 either way)."""
import json
import re
import sys

import ldb

from local_admin_store import ack_switch, read_switch, write_switch
from open_samdb import open_samdb
import paths

CONF = "/data/etc/smb.conf"
DC_RE = re.compile(r"^dc-\d{4}$")                # fabric names its DCs dc-NNNN (2.1.6.65)


def _is_dc(samdb, dc):
    """Purpose: whether the domain knows a DC of that name: its record in CN=dcs,CN=fabric,CN=System (2.1.6.79).
    Inputs:  samdb — SamDB; dc — str.
    Returns: bool.
    Fails:   ldb.LdbError other than "no such object".
    Feeds:   run."""
    try:
        samdb.search(base=paths.dc_record_dn(samdb, dc), scope=ldb.SCOPE_BASE, attrs=["cn"])
        return True
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise


def run(req):
    """Purpose: one switch operation: read at any DC; written only at a writable DC (a read-only one is refused,
             naming the writable DC to run it at).
    Inputs:  req — as the module says.
    Returns: get: read_switch's result; set and ack: {**read_switch's result, "changed": bool}.
    Fails:   ValueError for a request refused (its message is shown: ack while the switch is off); ldb.LdbError.
    Feeds:   this script's main."""
    samdb, _ = open_samdb(CONF)
    op, dc = req.get("op"), str(req.get("dc") or "").lower()
    if not DC_RE.match(dc) or not _is_dc(samdb, dc):
        raise ValueError(f"{dc or '(none)'} is no domain controller of this domain (its record in "
                         "CN=dcs,CN=fabric,CN=System): name one with --dc dc-NNNN")
    if op == "get":
        return read_switch(samdb, dc)
    if op not in ("set", "ack"):
        raise ValueError(f"unknown operation {op}")
    if not req.get("writable"):
        where = req.get("writable_dc") or "a writable domain controller"
        raise ValueError(f"this host's domain controller ({req.get('this_dc')}) is read-only: set the switch on the "
                         f"fabric host of {where}, naming this one (sudo fabricctl local-admin ssh on|off --dc {dc})")
    if op == "ack":
        changed = ack_switch(samdb, dc, str(req.get("by") or "root"), str(req.get("when") or ""))
        return {**read_switch(samdb, dc), "changed": changed}
    if not isinstance(req.get("ssh"), bool):
        raise ValueError("ssh: on or off")
    changed = write_switch(samdb, dc, req["ssh"], str(req.get("by") or "root"), str(req.get("when") or ""))
    return {**read_switch(samdb, dc), "changed": changed}


if __name__ == "__main__":
    try:
        print(json.dumps({"result": run(json.load(sys.stdin))}))
    except ValueError as e:                  # the switches' own refusals: shown as they are
        print(json.dumps({"error": str(e)}))
    except Exception as e:                   # anything else: its kind, for the log
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
