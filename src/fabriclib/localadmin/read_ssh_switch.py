from fabriclib.localadmin.local_admin_request import local_admin_request


def read_ssh_switch(v, dc=None, container="samba"):
    """Purpose: the SSH switch of a DC's host's local-admin as the domain keeps it (decision 2.1.7.19, manual
             1.7.1.4.6): off unless the Enterprise Admin turned it on.
    Inputs:  v — rendered vars (dc_name); dc — the DC whose host is meant (default this host's); container — the DC's
             container (tests name their own).
    Returns: {"dc", "ssh": bool, "by", "when", "ack"} ("by" and "when" None while it was never set; "ack" {"by",
             "when"} while its alert is acknowledged, 2.1.7.21, else None).
    Fails:   ValidationError when the DC does not answer (callers keep what they last applied).
    Feeds:   check_local_admin, local_admin_status."""
    return local_admin_request(v, {"op": "get", "dc": (dc or v["dc_name"]).lower()}, container)
