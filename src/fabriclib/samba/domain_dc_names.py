import json
import subprocess

from fabriclib.common.errors import ValidationError


def domain_dc_names(container="samba"):
    """Purpose: the computer names the domain holds, its domain controllers apart (manual 1.6.5.23), read inside this
             site's DC from its own database (src/containers/samba/read_dc_names.py).
    Inputs:  container — this site's DC.
    Returns: {"dcs": [name, …], "computers": [name, …]}, lower case, without the trailing $.
    Fails:   ValidationError when the DC does not answer (a name must never be guessed free).
    Feeds:   federation/accept_join (a joining site's DC name checked before its join is prepared)."""
    try:
        res = subprocess.run(["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                              "/fabric/read_dc_names.py"], capture_output=True, text=True, timeout=60)
        if res.returncode == 0:
            out = json.loads(res.stdout)
            return {"dcs": list(out["dcs"]), "computers": list(out["computers"])}
        why = (res.stderr.strip().splitlines() or ["no answer"])[-1]
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the domain's computer names could not be read from this site's DC: {why}")
