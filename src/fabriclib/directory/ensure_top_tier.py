import json
import subprocess

from fabriclib.common.errors import ValidationError


def ensure_top_tier(uid, container="samba"):
    """Purpose: setup's first admin made the Enterprise Admin (manual 1.6.12.2, 2.1.6.68): a member of Enterprise
             Admins, Schema Admins and Domain Admins, run inside the DC as the system (src/containers/samba/
             ensure_top_tier.py: fabric's agent accounts may not change AD's top tier), which then writes the denies
             that keep the Directory Administrators' rights off the top tier's accounts.
    Inputs:  uid — the person's user name (in OU=people); container — the DC's container (tests name their own).
    Returns: list of str, what changed (empty when they were the Enterprise Admin already).
    Fails:   ValidationError with the DC's message (no such person, the DC not running, AD refusing);
             subprocess.TimeoutExpired after 120 s.
    Feeds:   setup/create_admin (at the root site)."""
    res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          "/fabric/ensure_top_tier.py"], input=json.dumps({"uid": uid}), capture_output=True,
                         text=True, timeout=120)
    if res.returncode != 0:
        raise ValidationError("the first admin could not be made the Enterprise Admin: "
                              + ((res.stderr or res.stdout).strip().splitlines() or ["the DC is not running"])[-1])
    return json.loads(res.stdout)["changed"]
