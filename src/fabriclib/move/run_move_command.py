import getpass

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.move.check_new_address import check_new_address
from fabriclib.move.move_request import move_request

USAGE = """usage: fabricctl move prepare <new address>   tell the machines fabric manages the host's next address
       fabricctl move status                 the address announced, if any
       fabricctl move cancel                 withdraw it: the host is not moving
  Run prepare before changing the host's address, then wait for the machines: Linux checks hourly, Windows takes Group
  Policy within 90 minutes (or gpupdate). Machines fabric does not manage are still yours (manual 4.2.4.2)."""


def run_move_command(v, args, container="samba", registry=None, audit=write_audit):
    """Purpose: `fabricctl move ...` (manual 4.2.4.2, 1.4.1.8.7; decision 2.1.1.79): only routes to the DC and prints.
    Inputs:  v — rendered vars (site_name, dc_name, host_ip, lan_cidr, lan_gateway); args — list of str after `move`;
             container — the DC's container; registry — the federation registry, for tests; audit — the audit writer.
    Returns: exit status: 0 ok, 1 refused, 2 usage.
    Fails:   OSError writing the audit log (propagates).
    Feeds:   cli.main."""
    op = args[0] if args else ""
    if op not in ("prepare", "status", "cancel") or len(args) != (2 if op == "prepare" else 1):
        print(USAGE)
        return 2
    base = {"site": v["site_name"], "dc": v["dc_name"], "host_ip": v["host_ip"]}
    try:
        if op == "prepare":
            new = check_new_address(v, args[1], registry)
            out = move_request({**base, "op": "prepare", "new": new}, container)
            audit(getpass.getuser(), "MOVE_PREPARE", f"from={v['host_ip']} to={new}", "cli")
            print(f"announced: the host moves from {v['host_ip']} to {new}." if out["changed"]
                  else f"already announced: the host moves from {v['host_ip']} to {new}.")
            print("Wait for the machines before changing the address: Linux machines check hourly; Windows machines "
                  "take Group Policy within 90 minutes (or gpupdate). Then manual 4.2.4.2, step 2.")
        elif op == "status":
            out = move_request({**base, "op": "status"}, container)
            print(f"announced: the host moves from {out['old']} to {out['new']}." if out["new"]
                  else "no move announced")
        else:
            out = move_request({**base, "op": "cancel"}, container)
            if out["changed"]:
                audit(getpass.getuser(), "MOVE_CANCEL", f"from={v['host_ip']}", "cli")
            print("withdrawn: the machines go back to this address alone at their next check." if out["changed"]
                  else "no move announced")
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    return 0
