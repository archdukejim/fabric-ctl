from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def read_address_plan(v, secrets=None, container="samba"):
    """Purpose: the address plan across sites, from the domain (manual 1.10.2.8, S4.2): every site's networks with
             name, VLAN, kind and notes, as convergence wrote them in the domain's OU=networks (each
             `<site>/<name>`, 1.6.13.10.10).
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container (tests name their own).
    Returns: list of {"site", "name", "cidr", "vlan", "kind", "notes", "allow_overlap"}, sorted by site and
             network; [] before any site has converged.
    Fails:   ValidationError from run_op (the DC not reachable) or load_secrets, or without the agent's password
             in fabric's secrets (an install that has no domain yet).
    Feeds:   federation/show_networks (`fabricctl federation networks`), dhcp/common/edit_dhcp and accept_join
             (overlap checks)."""
    secrets = secrets if secrets is not None else load_secrets()
    if not secrets.get("ad_agent_password"):
        raise ValidationError("the domain cannot be asked: fabric's secrets have no ad_agent_password")
    return run_op(v, secrets, "read_networks", container=container)
