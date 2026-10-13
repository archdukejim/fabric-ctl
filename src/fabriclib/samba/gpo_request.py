import json
import subprocess

from fabriclib.common.errors import ValidationError


# the editor's operations that change the domain or SYSVOL; the others only read
WRITES = frozenset({"load", "set", "clear"})


def gpo_request(request, container="samba", v=None):
    """Purpose: one ADMX-editor operation inside the DC (src/containers/samba/gpo_tool.py, manual 1.6.5.20 S5.4),
             the request on stdin. The editor works on the DC's own database and SYSVOL, so it cannot be sent to
             another DC: at a site whose DC is read-only a change is refused before anything is asked (2.1.6.52,
             revised 2026-10-13); reads are answered there.
    Inputs:  request — dict (gpo_tool's request: op, site, …); container — the DC's container (tests name their own);
             v — fabric vars (ad_dc_type), or None (a read, or a caller that knows its DC is writable).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with the editor's refusal (e.g. "no policy … in the central store"), "the domain
             controller is not running", or for a change at a read-only DC's site why it is refused;
             subprocess.TimeoutExpired after 5 minutes.
    Feeds:   samba/run_gpo_command, set_gpo_policy, clear_gpo_policy, gpo_overview; tests/samba/gpo.py."""
    if request.get("op") in WRITES and (v or {}).get("ad_dc_type") == "rodc":
        raise ValidationError("this site's domain controller is read-only, and Group Policy is edited on a writable "
                              "domain controller's own copy: make the change at the site above (its GPOs reach this "
                              "site); nothing was changed")
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
