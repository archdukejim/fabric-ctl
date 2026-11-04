import json
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.directory import held_op


READS = {"templates", "policies", "show"}       # a held process may answer (2.1.8.35)


def gpo_request(request, container="samba"):
    """Purpose: one ADMX-editor operation inside the DC (src/containers/samba/gpo_tool.py, manual 1.6.5.20 S5.4),
             the request on stdin.
    Inputs:  request — dict (gpo_tool's request: op, site, …); container — the DC's container (tests name their own).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with the editor's refusal (e.g. "no policy … in the central store") or "the domain
             controller is not running"; subprocess.TimeoutExpired after 5 minutes.
    Feeds:   samba/run_gpo_command; tests/samba/gpo.py."""
    if held_op.enabled() and request.get("op") in READS:
        out = held_op.ask_tool(container, "gpo_tool", request)
    else:
        res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container,
                              "python3", "/fabric/gpo_tool.py"], input=json.dumps(request), capture_output=True,
                             text=True, timeout=300)
        if res.returncode != 0 or not res.stdout.strip():
            raise ValidationError("the domain controller is not running" if "is not running" in res.stderr
                                  or "No such container" in res.stderr else (res.stderr.strip() or "no answer")[-300:])
        out = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in out:
        raise ValidationError(out["error"])
    return out["result"]
