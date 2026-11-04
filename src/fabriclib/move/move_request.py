import json
import subprocess

from fabriclib.common.errors import ValidationError


def move_request(request, container="samba"):
    """Purpose: one operation on the announced move inside the DC (src/containers/samba/move_tool.py, manual
             1.4.1.8.7), the request on stdin.
    Inputs:  request — dict (move_tool's request: op, site, dc, host_ip, ...); container — the DC's container.
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with the DC's refusal or "the domain controller is not running";
             subprocess.TimeoutExpired after 5 minutes.
    Feeds:   run_move_command."""
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container,
                          "python3", "/fabric/move_tool.py"], input=json.dumps(request), capture_output=True,
                         text=True, timeout=300)
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("the domain controller is not running" if "is not running" in res.stderr
                              or "No such container" in res.stderr else (res.stderr.strip() or "no answer")[-300:])
    out = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in out:
        raise ValidationError(out["error"])
    return out["result"]
