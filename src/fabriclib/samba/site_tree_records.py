import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.samba.read_in_dc import read_in_dc


def site_tree_records(container="samba"):
    """Purpose: every site's record in the domain with its place in the federation (decision 2.1.8.30, manual
             1.8.6.12): its parent and its console's address, read inside this site's DC from its own database
             (src/containers/samba/read_site_tree.py), so every site sees every other's as the domain replicates.
    Inputs:  container — this site's DC.
    Returns: list of {"site", "parent" ("" for the root), "console" ("" when none is recorded)}, by name.
    Fails:   ValidationError when the DC does not answer (the caller shows why, never a guessed tree).
    Feeds:   federation/site_selector."""
    try:
        return list(read_in_dc(container, "read_site_tree", 30)["sites"])
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the sites' records could not be read from this site's DC: {why}")
