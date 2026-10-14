import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")     # a site, a role, a group or a person's name


def change_site_role(v, actor, target, role, member="", grant=True, source="web", secrets=None, container="samba"):
    """Purpose: grant a role at a site below this one, or take it back (2.1.9.21, manual 1.9.8.20): a site above puts a
             group or person (by default the site's own `<site>-admins`) in the role's group `<site>-<role>`; a
             console role then gives its bundle at that site only, an AD role its rights there (and in the sites
             below it). This install's own site and the sites beside or above it are refused (a branch cannot grant
             itself), by the DC's operation and by AD's limits on this site's agent.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; target — the site's name; role — a grantable
             role (`fabricctl federation roles` lists them); member — a group or person name ("" for
             `<target>-admins`); grant — bool, True to grant, False to revoke; source — audit source; secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"site", "role", "group", "member", "granted", "changed", "remade"} (remade: a group the site had made
             itself was replaced, 2.1.9.21).
    Fails:   ValidationError "site, role and member: …" for a malformed name; the DC's refusals word for word (a role
             that cannot be granted; "only a site above <site> may grant its roles…"; no such group or person;
             the group not made yet); "the directory refused the change …" (AD); load_secrets' errors.
    Feeds:   agent route POST /v1/federation/roles (federation:admin) via agent/post_federation;
             federation/run_federation_command (`fabricctl federation roles grant|revoke`).
    Notes:   audited as SITE_ROLE_GRANT / SITE_ROLE_REVOKE when it changed something."""
    for name in (target, role) + ((member,) if member else ()):
        if not NAME_RE.match(name or ""):
            raise ValidationError(f"site, role and member: letters, digits, . _ - (got {name!r})")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "grant_site_role",
                  {"target": target, "role": role, "member": member, "grant": bool(grant)}, container)
    if done.get("changed"):
        write_audit(actor, "SITE_ROLE_GRANT" if grant else "SITE_ROLE_REVOKE",
                    f"site={target} role={role} member={done.get('member')} group={done.get('group')}"
                    + (" remade=yes" if done.get("remade") else ""), source)
    return done
