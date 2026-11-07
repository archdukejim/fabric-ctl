"""The host's coming move inside the DC (decision 2.1.1.79, manual 1.4.1.8.7), run as root on its own database and
SYSVOL (no credentials, no network) by fabriclib/move/move_request:
    docker exec -i samba python3 /fabric/move_tool.py < request.json
The request on stdin: {"op": "prepare"|"status"|"cancel", "site", "dc", "host_ip", "new" (prepare)}. Prints one JSON
object: {"result": ...} or {"error": message} (exit 0 either way)."""
import json
import sys

from member_dns import announce, announced, ensure_member_dns, note_previous, withdraw
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
        move = announced(samdb, dc)
        if move and move[1] != req["new"]:      # a machine may have taken the one this replaces
            note_previous(samdb, dc, move[1], host)
        changed = announce(samdb, dc, host, req["new"])
    elif op == "cancel":
        move = announced(samdb, dc)
        changed = withdraw(samdb, dc)
        if move:            # a machine that took both addresses gives the one that never came back
            note_previous(samdb, dc, move[1], host)
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
