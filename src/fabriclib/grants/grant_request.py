import json
import os
import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.is_root_site import is_root_site


def grant_request(v, request, container="samba"):
    """Purpose: one grants operation inside the DC (src/containers/samba/grants_tool.py, manual 1.6.13.4), the request
             on stdin, with this DC's name and whether it is the root's writable DC (the one place grants are changed
             and compiled: their GPOs are the root's, the other DCs copy them).
    Inputs:  v — rendered vars (dc_name, ad_dc_type, deploy_base_dir: the federation registry under it); request —
             dict (grants_tool's request: op, …); container — the DC's container (tests name their own).
    Returns: the operation's result (JSON-decoded).
    Fails:   ValidationError with the DC's refusal word for word (e.g. "no grant x", "who: no group y in the domain",
             "grants are changed and compiled at the root site's writable DC …"), or "the domain controller is not
             running"; subprocess.TimeoutExpired after 5 minutes.
    Feeds:   the grants functions of this folder; tests/samba/grants.py."""
    registry = os.path.join(v["deploy_base_dir"], "fabric", "config", "federation.yaml")
    root = is_root_site(registry) and (v.get("ad_dc_type") or "writable") != "rodc"
    req = {**request, "dc": v["dc_name"], "writable_root": root}
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container,
                          "python3", "/fabric/grants_tool.py"], input=json.dumps(req), capture_output=True,
                         text=True, timeout=300)
    if res.returncode != 0 or not res.stdout.strip():
        raise ValidationError("the domain controller is not running" if "is not running" in res.stderr
                              or "No such container" in res.stderr else (res.stderr.strip() or "no answer")[-300:])
    out = json.loads(res.stdout.strip().splitlines()[-1])
    if "error" in out:
        raise ValidationError(out["error"])
    return out["result"]
