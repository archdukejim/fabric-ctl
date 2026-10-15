from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def remove_machine(v, actor, name, source="web", secrets=None, container="samba", server=None):
    """Purpose: remove a machine of this site from the domain (manual 1.6.7.6): it can no longer log anyone on or
             sign in to the network; joining again makes a new account.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the machine's host name; source — audit
             source; secrets — fabric's secrets (default: load_secrets()); container — the DC's container;
             server — None, or the writable DC to remove it at (a read-only DC's site, 2.1.6.52).
    Returns: {"name"}.
    Fails:   ValidationError from run_op ("no such entry": not a machine of this site; the DC not reachable).
    Feeds:   agent route POST /v1/machines/<name>/delete (machines:admin).
    Notes:   audited as MACHINE_REMOVE."""
    done = run_op(v, secrets if secrets is not None else load_secrets(), "remove_machine", {"name": name}, container,
                  server)
    write_audit(actor, "MACHINE_REMOVE", f"machine={name}", source)
    return done
