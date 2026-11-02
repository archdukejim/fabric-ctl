from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def read_scan_requests(v, site, secrets=None, container="samba"):
    """Purpose: the scan requests below a site's subnets, with their answers (decision 2.1.10.38, manual 1.10.4.36),
             read from this site's DC as its agent (the DC's operation read_scan_requests).
    Inputs:  v — fabric vars (site_name); site — the site whose requests are read; secrets — fabric's secrets (default
             load_secrets()); container — the DC's container.
    Returns: the operation's list: {"id", "site", "subnet", "cidr", "requested_by", "actor", "state", "result",
             "done_at", "created", "created_at" (epoch seconds), "owner", "by_agent" (bool: a fabric DC's agent
             account made it)}, oldest first.
    Fails:   ValidationError from run_op (the DC not reachable, no such site) or without the agent's password.
    Feeds:   list_scan_requests, request_scan, run_scan_requests."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    return run_op(v, secrets, "read_scan_requests", {"of": site}, container=container)
