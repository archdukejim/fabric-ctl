from fabriclib.directory.run_op import run_op


def write_plan(v, secrets, changes, container="samba", server=None):
    """Purpose: write checked changes to the address manager's plan in the domain (manual 1.10.4.33), as this DC's
             agent account, which has full control of OU=networks and CN=fabric,CN=System (1.6.13.10.4): who may ask
             is fabric-agent's check of the grants' networks rights, made before (common/edit_plan, 1.6.13.12).
    Inputs:  v — fabric vars (site_name, dc_name); secrets — fabric's secrets (ad_agent_password); changes —
             write_plan's changes ([{"do", "what", "site", "key", "subnet", "fields"}]); container — the DC's
             container; server — None (this DC) or a writable DC's address (a read-only DC's site,
             samba/writable_server, 2.1.6.52).
    Returns: list of str, what changed.
    Fails:   ValidationError from run_op ("no such site", "that name is already taken", the DC not reachable); the
             changes before a refused one stay made.
    Feeds:   common/edit_plan."""
    if not changes:
        return []
    return run_op(v, secrets, "write_plan", {"changes": changes}, container=container, server=server)
