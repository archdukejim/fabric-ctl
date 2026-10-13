from fabriclib.directory.run_op import run_op


def write_plan(v, secrets, changes, container="samba"):
    """Purpose: write checked changes to the address manager's plan in the domain (manual 1.10.4.13), as this site's
             agent account: AD decides which sites it may write (its own and those below it, 1.6.3.6).
    Inputs:  v — fabric vars (site_name); secrets — fabric's secrets (ad_agent_password); changes — write_plan's
             changes ([{"do", "what", "site", "key", "subnet", "fields"}]); container — the DC's container.
    Returns: list of str, what changed.
    Fails:   ValidationError from run_op ("the directory refused the change (not permitted for this site)", "that
             name is already taken", the DC not reachable); the changes before a refused one stay made.
    Feeds:   common/edit_plan, move_subnets_to_plan."""
    if not changes:
        return []
    return run_op(v, secrets, "write_plan", {"changes": changes}, container=container)
