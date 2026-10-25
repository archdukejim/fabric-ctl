import json
import subprocess

from fabriclib.common.errors import ValidationError


def domain_sites(container="samba"):
    """Purpose: every DC's record in the domain as this site's DC holds it (manual 1.6.13.2, 2.1.6.79), each with its
             site: read inside the DC from its own database (src/containers/samba/read_sites.py), so a site that
             already exists (one moving here, 2.1.6.20) is recognised.
    Inputs:  container — this site's DC.
    Returns: list of {"dc", "site", "id_range"}.
    Fails:   ValidationError when the DC does not answer (a site's presence must never be guessed).
    Feeds:   federation/accept_join (a site moving here)."""
    try:
        res = subprocess.run(["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                              "/fabric/read_sites.py"], capture_output=True, text=True, timeout=60)
        if res.returncode == 0:
            return list(json.loads(res.stdout)["dcs"])
        why = (res.stderr.strip().splitlines() or ["no answer"])[-1]
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the domain's sites could not be read from this site's DC: {why}")
