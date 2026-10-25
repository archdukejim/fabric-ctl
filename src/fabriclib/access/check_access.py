from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.grants.grant_request import grant_request
from fabriclib.keycloak.fabric_groups import fabric_groups


def check_access(v, caller, action, target=None, container="samba"):
    """Purpose: fabric-agent's check of a call, console and CLI alike (manual 1.6.12.2, 1.6.12.11; 2.1.6.66 to
             2.1.6.68, 2.1.6.73), made inside the DC from the directory as it is (grants_tool's authorize): the tiers
             (nothing below a tier touches it or its members), the grants' people and machines rights, a group's two
             levels (its scope and managers by the tier above, its members by that tier or its managers within their
             controls). Called first by every function that changes a person, a machine or a group, before anything
             is written, so a refusal changes nothing.
    Inputs:  v — rendered vars (dc_name, deploy_base_dir; ldap_groups: the groups carrying a role bundle); caller —
             the signed-in person's user name (the agent's token), or None (root: the CLI, or a root peer of the
             agent, acting for the Enterprise Admin); action — authorize_action's ("people:reset", "machines:move",
             "groups:members", "domain:admin", ...); target — its target ({"name"}, {"groups"}, {"name", "member",
             "add"}, or None); container — the DC's container (tests name their own).
    Returns: {"tier": "enterprise"|"directory"|"delegated", "by": "tier"|"manager"|"grant <names>"}.
    Fails:   ValidationError saying why it is refused (e.g. "no grant gives you people reset on bob (manual
             1.6.13.4)", "bob is a Directory Administrator: only the Enterprise Admin …"), or "the domain controller is
             not running".
    Feeds:   the functions of fabriclib/directory and fabriclib/domain that change the directory.
    Notes:   root's "domain:admin" (a policy, a grant: no object) is allowed without asking the DC."""
    if caller is None and action == "domain:admin":     # root acts for the Enterprise Admin: no object to check
        return {"tier": "enterprise", "by": "tier"}
    bundles = sorted(fabric_groups(v) - {DIRECTORY_ADMINS})
    return grant_request(v, {"op": "authorize", "caller": caller, "action": action, "target": target or {},
                             "bundles": bundles}, container)
