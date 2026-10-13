import json
import subprocess

from fabriclib.common.errors import ValidationError


def read_usn(container="samba"):
    """Purpose: this site's DC's highest committed USN (decision 2.1.10.24, manual 1.10.4.26): the plan poll's first,
             cheap step, run inside the DC's container by src/containers/samba/read_usn.py (an anonymous read of the
             root DSE: no secret is loaded for it).
    Inputs:  container — the DC's container.
    Returns: int.
    Fails:   ValidationError "the domain controller did not give its USN (…)" when the container is not running or
             the read fails; subprocess.TimeoutExpired after 30 s.
    Feeds:   poll_plan."""
    res = subprocess.run(["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                          "/fabric/read_usn.py"], capture_output=True, text=True, timeout=30)
    try:
        answer = json.loads((res.stdout.strip().splitlines() or ["{}"])[-1])
    except ValueError:
        answer = {}
    if res.returncode != 0 or "usn" not in answer:
        why = answer.get("error") or (res.stderr.strip().splitlines() or ["is the samba service running?"])[-1]
        raise ValidationError(f"the domain controller did not give its USN ({why})")
    return int(answer["usn"])
