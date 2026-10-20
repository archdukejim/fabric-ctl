from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.directory.run_op import run_op
from fabriclib.keycloak.fabric_groups import fabric_groups
from fabriclib.secrets.load_secrets import load_secrets


def show_group(v, name, secrets=None, container="samba"):
    """Purpose: one group's two levels (manual 1.6.12.5): its scope (the grants and sudo rules naming it, the role
             bundle it carries, and 802.1X's people mapping from the settings), its managers and their controls, its
             members.
    Inputs:  v — rendered vars (ldap_groups, radius_people); name — the group's name; secrets — fabric's secrets
             (default: load_secrets()); container — the DC's container.
    Returns: the DC's group_scope, its scope with "bundle_name" (the bundle, or "") and "radius_vlan" (or None).
    Fails:   ValidationError "no group <name> in the domain"; run_op's.
    Feeds:   agent route GET /v1/groups/<name>; domain/run_group_command (scope)."""
    out = run_op(v, secrets if secrets is not None else load_secrets(), "group_scope",
                 {"name": name, "bundles": sorted(fabric_groups(v) - {DIRECTORY_ADMINS})}, container)
    low = out["name"].lower()
    out["scope"]["bundle_name"] = next((str(g.get("bundle")) for g in v.get("ldap_groups") or []
                                        if str(g.get("name", "")).lower() == low and g.get("bundle")), "")
    out["scope"]["radius_vlan"] = next((m.get("vlan") for m in v.get("radius_people") or []
                                        if str(m.get("group", "")).lower() == low), None)
    return out
