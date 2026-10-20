from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def place_fabric_host(v, actor, name, source="setup", secrets=None, container="samba", server=None):
    """Purpose: make the host's own computer account a fabric host (decisions 2.1.6.49, 2.1.6.70; manual 1.6.11.11,
             1.6.13.6): in the domain's OU=fabric-hosts, a member of `fabric-managed` and `dc-hosts`, marked as a
             fabric host; as this DC's agent account, so AD's ACLs apply.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the account's name without its $ (any
             case); source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container (tests name their own); server — None, or the writable DC to write at: a read-only DC's
             site, whose host's account then also goes into rodc-cache-<dc_name> (2.1.6.52, 2.1.6.85).
    Returns: the operation's result: {"name", "dn", "moved", "joined", "cached"}.
    Fails:   ValidationError from run_op ("no such entry": no such machine, or OU=fabric-hosts not converged yet;
             the DC not reachable).
    Feeds:   setup/join_host_domain.
    Notes:   audited as MACHINE_PLACE when it moved the account or made it a member."""
    done = run_op(v, secrets if secrets is not None else load_secrets(), "place_fabric_host",
                  {"name": name, "rodc_cache": bool(server)}, container, server)
    if done.get("moved") or done.get("joined"):
        write_audit(actor, "MACHINE_PLACE", f"machine={name.lower()} ou=fabric-hosts"
                    + "".join(f" {g}" for g in done.get("joined") or []), source)
    return done
