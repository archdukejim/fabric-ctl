from fabriclib.access.check_access import check_access
from fabriclib.common.write_audit import write_audit
from fabriclib.grants.grant_request import grant_request
from fabriclib.grants.read_grant_fields import read_grant_fields


def set_grant(v, actor, name, fields, source="cli", container="samba", caller=None):
    """Purpose: a grant changed (manual 1.6.13.4): the fields given replace the stored ones, the whole grant is checked
             again, stored and compiled at once. Its kind (allowing or restricting) is kept.
    Inputs:  v — rendered vars; actor — str, for the audit; name — the grant's name; fields — dict (read_grant_fields'
             keys); source — audit source; container — the DC's container; caller — the signed-in person's user name
             (fabric-agent's check: grants are the Directory Administrators' alone, 2.1.6.73), or None (root).
    Returns: {"grant", "changed"}.
    Fails:   ValidationError from check_access (only a Directory Administrator), read_grant_fields, "no grant <name>",
                 the DC's refusals (check_grant; "a grant's kind
             … is kept"; not the root's writable DC).
    Feeds:   agent route POST /v1/domain/grants/<name> (groups:admin); grants/run_grant_command (`grant set`).
    Notes:   audited GRANT_SET with the fields changed, and GRANT_COMPILE with what changed."""
    given = read_grant_fields(fields)
    check_access(v, caller, "domain:admin", {}, container)
    done = grant_request(v, {"op": "set", "name": name, "fields": given}, container)
    shown = " ".join(f"{k}={','.join(x) if isinstance(x, list) else x}" for k, x in sorted(given.items()))
    write_audit(actor, "GRANT_SET", f"grant={name} {shown}", source)
    if done["changed"]:
        write_audit(actor, "GRANT_COMPILE", "; ".join(done["changed"])[:2000], source)
    return done
