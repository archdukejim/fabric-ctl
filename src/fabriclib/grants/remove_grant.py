from fabriclib.common.write_audit import write_audit
from fabriclib.grants.grant_request import grant_request


def remove_grant(v, actor, name, source="cli", container="samba"):
    """Purpose: a grant removed (manual 1.6.13.4) and the rest compiled at once: its computed groups and sudo rule go,
             its machines fall into the sets the other grants make, or to the fallback (2.1.6.87).
    Inputs:  v — rendered vars; actor — str, for the audit; name — the grant's name; source — audit source;
             container — the DC's container.
    Returns: {"name", "changed"}.
    Fails:   ValidationError "no grant <name>", or not the root's writable DC.
    Feeds:   agent route POST /v1/domain/grants/<name>/delete (groups:admin); grants/run_grant_command
             (`grant remove`).
    Notes:   audited GRANT_REMOVE, and GRANT_COMPILE with what changed."""
    done = grant_request(v, {"op": "remove", "name": name}, container)
    write_audit(actor, "GRANT_REMOVE", f"grant={name}", source)
    if done["changed"]:
        write_audit(actor, "GRANT_COMPILE", "; ".join(done["changed"])[:2000], source)
    return done
