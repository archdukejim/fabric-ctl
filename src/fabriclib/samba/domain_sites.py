import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.samba.read_in_dc import read_in_dc


def domain_sites(container="samba"):
    """Purpose: every DC's record in the domain as this site's DC holds it (manual 1.6.13.2, 2.1.6.79), each with its
             site: read inside the DC from its own database (src/containers/samba/read_sites.py), so a site that
             already exists (one moving here, 2.1.6.20) is recognised.
    Inputs:  container — this site's DC.
    Returns: list of {"dc", "site", "id_range"}.
    Fails:   ValidationError when the DC does not answer (a site's presence must never be guessed).
    Feeds:   federation/accept_join (a site moving here)."""
    try:
        return list(read_in_dc(container, "read_sites")["dcs"])
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the domain's sites could not be read from this site's DC: {why}")
