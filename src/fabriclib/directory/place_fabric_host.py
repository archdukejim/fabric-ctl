from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def place_fabric_host(v, actor, name, source="setup", secrets=None, container="samba"):
    """Purpose: make the host's own computer account this site's fabric host (decision 2.1.6.49, manual 1.6.11.11): in
             the site's OU=fabric-hosts, a member of <site>-fabric-machines, marked as the fabric host; as the site's
             agent account, so AD's per-site limits apply.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the account's name without its $ (any
             case); source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container (tests name their own).
    Returns: the operation's result: {"name", "dn", "moved", "joined"}.
    Fails:   ValidationError from run_op ("no such entry": no such machine in this site, or the site's OU=fabric-hosts
             not converged yet; the DC not reachable).
    Feeds:   setup/join_host_domain.
    Notes:   audited as MACHINE_PLACE when it moved the account or made it a member."""
    done = run_op(v, secrets if secrets is not None else load_secrets(), "place_fabric_host", {"name": name}, container)
    if done.get("moved") or done.get("joined"):
        write_audit(actor, "MACHINE_PLACE", f"machine={name.lower()} ou=fabric-hosts"
                    + (" fabric-machines" if done.get("joined") else ""), source)
    return done
