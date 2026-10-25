import json
import subprocess

from fabriclib.common.errors import ValidationError


def site_tree_records(container="samba"):
    """Purpose: every site's record in the domain with its place in the federation (decision 2.1.8.30, manual
             1.8.6.12): its parent and its console's address, read inside this site's DC from its own database
             (src/containers/samba/read_site_tree.py), so every site sees every other's as the domain replicates.
    Inputs:  container — this site's DC.
    Returns: list of {"site", "parent" ("" for the root), "console" ("" when none is recorded)}, by name.
    Fails:   ValidationError when the DC does not answer (the caller shows why, never a guessed tree).
    Feeds:   federation/site_selector."""
    try:
        res = subprocess.run(["docker", "exec", "-e", "PYTHONDONTWRITEBYTECODE=1", container, "python3",
                              "/fabric/read_site_tree.py"], capture_output=True, text=True, timeout=30)
        if res.returncode == 0:
            return list(json.loads(res.stdout)["sites"])
        why = (res.stderr.strip().splitlines() or ["no answer"])[-1]
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the sites' records could not be read from this site's DC: {why}")
