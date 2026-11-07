import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.samba.read_in_dc import read_in_dc


def domain_dc_names(container="samba"):
    """Purpose: the computer names the domain holds, its domain controllers apart (manual 1.6.5.23), read inside this
             site's DC from its own database (src/containers/samba/read_dc_names.py).
    Inputs:  container — this site's DC.
    Returns: {"dcs": [name, …], "computers": [name, …]}, lower case, without the trailing $.
    Fails:   ValidationError when the DC does not answer (a name must never be guessed free).
    Feeds:   federation/accept_join (the lowest free name given to a joining site's DC before its join is prepared,
             2.1.6.65)."""
    try:
        out = read_in_dc(container, "read_dc_names")
        return {"dcs": list(out["dcs"]), "computers": list(out["computers"])}
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        why = str(e)
    raise ValidationError(f"the domain's computer names could not be read from this site's DC: {why}")
