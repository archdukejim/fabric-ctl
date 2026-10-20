from fabriclib.keycloak.quote import q
from fabriclib.keycloak.step import step


def grant_role_to_group(kc, realm, role_rep, group_name):
    """Purpose: give a Keycloak group a realm role, if it does not have it yet.
    Inputs:  kc — Admin; realm — realm name; role_rep — the role representation (needs "name"); group_name — exact group
             name.
    Returns: None; prints a step when granted. A missing group prints "! group '<name>' not found ... manually" and
             returns without error.
    Fails:   SystemExit from Admin.call.
    Feeds:   configure_keycloak (the admin bundle to directory-admins, and each ldap_groups bundle)."""
    _, groups = kc.call("GET", f"/{q(realm)}/groups?search={q(group_name)}&exact=true&briefRepresentation=true")
    group = next((g for g in groups if g.get("name") == group_name), None)
    if group is None:
        print(f"  ! group '{group_name}' not found in Keycloak; assign role '{role_rep['name']}' to admins manually")
        return
    _, mapped = kc.call("GET", f"/{q(realm)}/groups/{group['id']}/role-mappings/realm")
    if not any(r["name"] == role_rep["name"] for r in mapped):
        kc.call("POST", f"/{q(realm)}/groups/{group['id']}/role-mappings/realm", [role_rep])
        step(f"granted {role_rep['name']} to group {group_name}")
