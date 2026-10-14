from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.federation.change_site_role import NAME_RE
from fabriclib.secrets.load_secrets import load_secrets


def remake_site_group(v, actor, target, role, source="web", secrets=None, container="samba"):
    """Purpose: make one of a site below's role groups again (2.1.9.21, manual 4.9.1.2; 2.3.9.2.8 option (a)): a group
             the site made itself (which convergence refuses) is replaced, empty; a missing one is made; `admins`
             names `<site>-admins`. This install's own site and the sites beside or above it are refused, by the DC's
             operation and by AD's limits on this site's agent.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; target — the site's name; role — "admins" or a
             grantable role; source — audit source; secrets — fabric's secrets (default: load_secrets()); container —
             the DC's container.
    Returns: {"site", "role", "group", "remade", "made", "changed"}.
    Fails:   ValidationError "site and role: …" for a malformed name; the DC's refusals word for word (not a group a
             site above can make again; "only a site above <site> may make its groups again…"); "the directory
             refused the change …" (AD); load_secrets' errors.
    Feeds:   agent route POST /v1/federation/roles (action remake, federation:admin) via agent/post_federation;
             federation/run_roles_command (`fabricctl federation roles remake`).
    Notes:   audited as SITE_GROUP_REMAKE when it changed something."""
    for name in (target, role):
        if not NAME_RE.match(name or ""):
            raise ValidationError(f"site and role: letters, digits, . _ - (got {name!r})")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "remake_site_group",
                  {"target": target, "role": role}, container)
    if done.get("changed"):
        write_audit(actor, "SITE_GROUP_REMAKE", f"site={target} role={role} group={done.get('group')} "
                    f"{'remade' if done.get('remade') else 'made'}=yes", source)
    return done
