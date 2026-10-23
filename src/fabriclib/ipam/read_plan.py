from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def read_plan(v, secrets=None, of="", container="samba"):
    """Purpose: the address manager's plan from the domain (manual 1.10.4.32, 1.10.4.33), read as this DC's agent
             account (any DC holds it, a read-only one too): one site's (`of`) or every site's, with every site's
             record (its number and when it was made) and the option sets.
    Inputs:  v — fabric vars (site_name, dc_name); secrets — fabric's secrets (default: load_secrets()); of — a site's
             name, "" for every site; container — the DC's container (tests name their own).
    Returns: read_plan's result: {"sites": [{"name", "created", "block"}], "plans": {site: {"vlans", "subnets",
             "networks", "options"}}, "option_sets": {"domain": …, <site>: …}, "options"}.
    Fails:   ValidationError from run_op (the DC not reachable; "no such site: <of>" for a site with no record), from
             load_secrets, or without the agent's password in fabric's secrets (no domain yet).
    Feeds:   common/edit_plan (every change), show, find, export and block (run_ipam_command); later areas' apply
             and upgrade (1.10.4.41)."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    return run_op(v, secrets, "read_plan", {"of": of}, container=container)
