from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.grants.sync_grants import sync_grants
from fabriclib.secrets.load_secrets import load_secrets


def set_machine_site(v, actor, name, site, member, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: a computer put in a site or taken out (manual 1.6.12.6, Sites; `machines:admin`): its `site-<name>`
             group, and so the grants on that site, at once (compiled); after fabric-agent's check (a grant's machines
             groups reaching it, or a Directory Administrator).
    Inputs:  v — rendered vars; actor — str, for the audit; name — the host name; site — the site's name; member — bool;
             caller — the signed-in person's user name, or None (root); source — audit source; secrets — fabric's
             secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name", "site", "member", "changed"}.
    Fails:   ValidationError "name and site must be text"; check_access's; the DC's (no such site, no such machine, a
             fabric host).
    Feeds:   agent route POST /v1/machines/<name>/sites; domain/run_machine_command (sites).
    Notes:   audited MACHINE_SITE_ADD / MACHINE_SITE_REMOVE when it changed something."""
    if not isinstance(name, str) or not isinstance(site, str) or not site:
        raise ValidationError("name and site must be text")
    check_access(v, caller, "machines:groups", {"name": name}, container)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_machine_site",
                  {"name": name, "site_name": site, "member": bool(member)}, container)
    if done["changed"]:
        write_audit(actor, "MACHINE_SITE_ADD" if member else "MACHINE_SITE_REMOVE", f"machine={name} site={site}",
                    source)
        sync_grants(v, actor, source, container, quiet=True)
    return done
