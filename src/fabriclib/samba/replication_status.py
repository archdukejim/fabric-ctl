import subprocess

from fabriclib.samba.read_in_dc import read_in_dc


def replication_status(container="samba"):
    """Purpose: how this site's DC replicates with the others (manual 1.9.8.5, 1.9.8.9): every inbound neighbour per
             partition, when it last succeeded and how often it has failed since — AD's own record (`repsFrom`), read
             inside the DC from its database (src/containers/samba/read_replication.py), so a read-only DC shows it
             too.
    Inputs:  container — the DC's container.
    Returns: {"neighbours": [{"partition", "from" (the partner DC's NTDS settings DN), "last_success", "failures"
             (int), "message"}], "error": "" or why the DC could not be asked}.
    Fails:   never (a DC that does not answer gives error and no neighbours).
    Feeds:   federation/federation_overview (the Federation tab)."""
    try:
        return {"neighbours": read_in_dc(container, "read_replication")["neighbours"], "error": ""}
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
        return {"neighbours": [], "error": str(e)}
