import json
import subprocess

from fabriclib.common.errors import ValidationError


def run_rodc_lost(request, container="samba"):
    """Purpose: one step of handling a lost read-only DC (decision 2.1.6.58), run inside this site's writable DC as
             the system (src/containers/samba/rodc_lost.py), the request on stdin.
    Inputs:  request — {"action": "list" | "reset" | "remove", "site", ...} (rodc_lost.py's); container — the DC's.
    Returns: the step's JSON answer.
    Fails:   ValidationError "this site's writable domain controller does not answer …" (not running, or no answer)
             or "the domain controller refused it: …" (the step's own error, e.g. this DC read-only, an account not
             in the revealed list); subprocess.TimeoutExpired after 10 minutes.
    Feeds:   federation/rodc_lost."""
    try:
        res = subprocess.run(["docker", "exec", "-i", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                              "/fabric/rodc_lost.py"], input=json.dumps(request), capture_output=True, text=True,
                             timeout=600)
    except OSError as e:
        raise ValidationError(f"this site's writable domain controller does not answer ({e}): nothing was changed")
    lines = res.stdout.strip().splitlines()
    try:
        answer = json.loads(lines[-1]) if lines else None
    except ValueError:
        answer = None
    if not isinstance(answer, dict):
        why = (res.stderr.strip().splitlines() or ["is the samba service running?"])[-1]
        raise ValidationError(f"this site's writable domain controller does not answer ({why}): nothing was changed")
    if "error" in answer:
        raise ValidationError(f"the domain controller refused it: {answer['error']}")
    return answer
