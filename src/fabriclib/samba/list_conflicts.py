import subprocess

from fabriclib.samba.read_in_dc import read_in_dc


def list_conflicts(container="samba"):
    """Purpose: the objects AD renamed `CNF:` after the same name was made on two DCs while they were apart (manual
             1.9.8.5, Q12): one of each pair is a duplicate for an admin to resolve. Read from this DC's own database.
    Inputs:  container — the DC's container.
    Returns: list of str, the DNs (empty when there are none or the DC does not answer).
    Fails:   never.
    Feeds:   federation/federation_overview (the Federation tab)."""
    try:
        return list(read_in_dc(container, "read_conflicts")["conflicts"])
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError):
        return []
