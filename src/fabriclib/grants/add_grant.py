from fabriclib.access.check_access import check_access
from fabriclib.common.write_audit import write_audit
from fabriclib.grants.grant_request import grant_request
from fabriclib.grants.read_grant_fields import read_grant_fields


def add_grant(v, actor, name, fields, template=None, source="cli", container="samba", caller=None):
    """Purpose: a new grant (manual 1.6.13.4, 2.1.6.73, 2.1.6.77), from a template's rights or none, stored and
             compiled at once (its computed groups, its machines' set and GPO, its sudo rule), so it holds at the
             machines' next sign-in.
    Inputs:  v — rendered vars; actor — str, for the audit; name — the grant's name; fields — dict (read_grant_fields'
             keys); template — a template's name (helpdesk, limited-directory-administrator, site-networks) or None;
             source — audit source; container — the DC's container; caller — the signed-in person's user name
             (fabric-agent's check: grants are the Directory Administrators' alone, 2.1.6.73), or None (root).
    Returns: {"grant": the stored grant, "changed": [what the compile changed]}.
    Fails:   ValidationError from check_access ("only a Directory Administrator may do this"), read_grant_fields,
             or the DC's refusal, with why (check_grant: the tiers' groups, the DC hosts, sudo of every command for
             everyone, an empty who or where, ...; "a grant <name> exists"; not the
             root's writable DC).
    Feeds:   agent route POST /v1/domain/grants (groups:admin); grants/run_grant_command (`grant add`).
    Notes:   audited GRANT_ADD with the grant (its networks rights and sites too), and GRANT_COMPILE with what
             changed."""
    check_access(v, caller, "domain:admin", {}, container)
    request = {"op": "add", "name": name, "fields": read_grant_fields(fields)}
    if template:
        request["template"] = template
    done = grant_request(v, request, container)
    g = done["grant"]
    networks = f" networks={','.join(g['networks'])} sites={','.join(g['sites'])}" if g.get("networks") else ""
    write_audit(actor, "GRANT_ADD", f"grant={name} kind={g['kind']} who={','.join(g['who'])} "
                f"where={','.join(g['where'])}{networks}", source)
    if done["changed"]:
        write_audit(actor, "GRANT_COMPILE", "; ".join(done["changed"])[:2000], source)
    return done
