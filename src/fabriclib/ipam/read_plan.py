from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def read_plan(v, secrets=None, of="", container="samba"):
    """Purpose: the address manager's plan from the domain (manual 1.10.4.4, 1.10.4.13), read as this site's agent
             account: one site's (`of`) or every site's, with every site's number and order.
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()); of — a site's name,
             "" for every site; container — the DC's container (tests name their own).
    Returns: read_plan's result: {"sites": [{"name", "created", "block"}], "plans": {site: {"vlans", "subnets",
             "networks"}}}.
    Fails:   ValidationError from run_op (the DC not reachable, a site with no OU: "no such entry"), from
             load_secrets, or without the agent's password in fabric's secrets (no domain yet).
    Feeds:   load_address_plan (an apply), common/edit_plan (every change), move_subnets_to_plan, show_plan,
             find_in_plan, export_plan."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    return run_op(v, secrets, "read_plan", {"of": of}, container=container)
