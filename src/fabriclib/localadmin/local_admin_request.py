import json
import subprocess

from fabriclib.common.errors import ValidationError


def local_admin_request(v, request, container="samba"):
    """Purpose: one operation on the local-admin switches kept in the domain (src/containers/samba/local_admin_tool.py,
             manual 1.7.1.4.6), the request on stdin, run inside this host's DC as the system, with this DC's name and
             whether it is writable (switches are written only at a writable DC; read at any).
    Inputs:  v — rendered vars (dc_name, ad_dc_type, ad_join_server_name: the writable DC of a read-only DC's site);
             request — dict (op "get", "set" or "ack", "dc", for set "ssh", for set and ack "by" and "when");
             container — the DC's container
             (tests name their own).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with the DC's refusal word for word, or "the domain controller is not running";
             subprocess.TimeoutExpired after 2 minutes.
    Feeds:   read_ssh_switch, set_local_admin_ssh, ack_local_admin_ssh; tests/samba/domain.py."""
    req = {**request, "this_dc": v["dc_name"], "writable": (v.get("ad_dc_type") or "writable") != "rodc",
           "writable_dc": v.get("ad_join_server_name") or ""}
    try:
        res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container,
                              "python3", "/fabric/local_admin_tool.py"], input=json.dumps(req), capture_output=True,
                             text=True, timeout=120)
    except FileNotFoundError:
        raise ValidationError("the domain controller is not running (no docker)")
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("the domain controller is not running" if "is not running" in res.stderr
                              or "No such container" in res.stderr else (res.stderr.strip() or "no answer")[-300:])
    out = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in out:
        raise ValidationError(out["error"])
    return out["result"]
