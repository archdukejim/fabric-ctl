from fabriclib.access.check_access import check_access
from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets


def remove_group(v, actor, name, caller=None, source="web", secrets=None, container="samba"):
    """Purpose: an admin's own group deleted (manual 1.6.12.5, Delete group; `groups:admin`), after fabric-agent's
             check (the tier above the group); refused, naming where, while it is in use: 802.1X's people mapping (the
             settings' radius_people), a grant, a sudo rule, another group's managers; refused for fabric's and AD's
             own groups.
    Inputs:  v — rendered vars (radius_people, ldap_groups); actor — str, for the audit; name — the group's name;
             caller — the signed-in person's user name, or None (root); source — audit source; secrets — fabric's
             secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name"}.
    Fails:   ValidationError: "<name> is in use: 802.1X's people mapping …"; check_access's; the DC's ("no group …",
             "<name> is one of fabric's own groups …: not deleted", "<name> is in use: grant …").
    Feeds:   agent route POST /v1/groups/<name>/delete; domain/run_group_command (delete).
    Notes:   audited GROUP_REMOVE."""
    check_access(v, caller, "groups:admin", {"name": name}, container)
    if str(name).lower() in {str(g.get("name", "")).lower() for g in v.get("ldap_groups") or []}:
        raise ValidationError(f"{name} is one of fabric's own groups (the settings' ldap_groups, made at every "
                              "convergence): not deleted")
    mapped = [m for m in v.get("radius_people") or [] if str(m.get("group", "")).lower() == str(name).lower()]
    if mapped:
        raise ValidationError(f"{name} is in use: 802.1X's people mapping (VLAN {mapped[0].get('vlan')}): unmap it "
                              "first (fabricctl radius people)")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "remove_group",
                  {"name": name, "bundles": sorted(fabric_groups(v) - {DIRECTORY_ADMINS})}, container)
    write_audit(actor, "GROUP_REMOVE", f"group={done['name']}", source)
    return done
