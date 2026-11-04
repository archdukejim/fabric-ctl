"""The host's coming move inside the DC (decision 2.1.1.79, manual 1.4.1.8.7), run as root on its own database and
SYSVOL (no credentials, no network) by fabriclib/move/move_request:
    docker exec -i samba python3 /fabric/move_tool.py < request.json
The request on stdin: {"op": "prepare"|"status"|"cancel", "site", "dc", "host_ip", "new" (prepare)}. Prints one JSON
object: {"result": ...} or {"error": message} (exit 0 either way)."""
import json
import sys

from member_dns import announce, announced, ensure_member_dns, withdraw
from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"


def run(req):
    """Purpose: one operation.
    Inputs:  req — the request (above).
    Returns: prepare: {"changed", "done"}; status: {"old", "new"} ("" when none); cancel: {"changed", "done"}.
    Fails:   ValueError for an unknown operation; ldb.LdbError, OSError.
    Feeds:   this script's main."""
    samdb, lp = open_samdb(CONF)
    op, site, dc, host = req.get("op"), req.get("site"), req.get("dc"), req.get("host_ip")
    if op == "status":
        move = announced(samdb, dc)
        return {"old": move[0] if move else "", "new": move[1] if move else ""}
    if op == "prepare":
        changed = announce(samdb, dc, host, req["new"])
    elif op == "cancel":
        changed = withdraw(samdb, dc)
    else:
        raise ValueError(f"unknown operation {op}")
    return {"changed": changed, "done": ensure_member_dns(samdb, lp, site, dc, host)}


def main():
    """Purpose: read the request, print the result or the refusal as one JSON line.
    Inputs:  stdin.
    Returns: None.
    Fails:   json.JSONDecodeError for a request that is not JSON.
    Feeds:   docker exec."""
    try:
        print(json.dumps({"result": run(json.load(sys.stdin))}))
    except ValueError as e:
        print(json.dumps({"error": str(e)}))


if __name__ == "__main__":
    main()
