from fabriclib.keycloak.fabric_groups import fabric_groups


def privileged_groups(v):
    """Purpose: the organisation's groups whose members hold a role at every site (the console's admin group, the
             bundle groups, `fabric-admins`, `fabric-break-glass`): what the DC counts as a role at the top site
             (2.1.9.21, 2.1.9.24).
    Inputs:  v — fabric vars (fabric_groups' keys).
    Returns: sorted list of str.
    Fails:   as fabric_groups.
    Feeds:   samba/converge_domain, samba/prepare_site, directory/set_person_group, directory/move_person,
             federation/site_roles."""
    return sorted(fabric_groups(v) | {"fabric-admins", "fabric-break-glass"})
