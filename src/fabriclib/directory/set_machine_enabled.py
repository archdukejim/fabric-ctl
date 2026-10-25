from fabriclib.access.check_access import check_access
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def set_machine_enabled(v, actor, name, enabled, source="web", secrets=None, container="samba", caller=None):
    """Purpose: disable a machine of this site, or enable it again (manual 1.6.7.6): while disabled its logons and
             its PEAP sign-in are refused; its account stays.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the machine's host name; enabled — bool;
             source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container; caller — the signed-in person's user name (fabric-agent's check: a grant's machines disable
             reaching it, or a Directory Administrator), or None (root).
    Returns: {"name", "enabled", "changed"}.
    Fails:   ValidationError from check_access (why it is refused; not asked for source "setup", fabric's own
             change of the fabric host's account), or run_op ("no such entry": not a machine of this site;
             the DC not reachable).
    Feeds:   agent route POST /v1/machines/<name>/enable|disable (machines:admin).
    Notes:   audited as MACHINE_ENABLE / MACHINE_DISABLE when it changed something."""
    if source != "setup":            # setup changing the fabric host's own account is fabric's, not a person's
        check_access(v, caller, "machines:disable", {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_machine",
                  {"name": name, "enabled": bool(enabled)}, container)
    if done.get("changed"):
        write_audit(actor, "MACHINE_ENABLE" if enabled else "MACHINE_DISABLE", f"machine={name}", source)
    return done
