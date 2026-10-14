from fabriclib.keycloak.quote import q
from fabriclib.keycloak.step import step

LDAP_MAPPER = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
SITE_MAPPER = "fabric site groups"      # ensure_site_group_mapper's: never this one's to take over (2.1.9.21)


def ensure_group_mapper(kc, realm, ldap_id, v):
    """Purpose: create or update the LDAP group mapper on fabric's groups in AD (OU=groups of OU=organisation, AD's
             memberOf; LDAP_ONLY: memberships live in AD) and sync them into Keycloak (manual 1.6.3.11).
    Inputs:  kc — Admin; realm — realm name; ldap_id — federation id from ensure_ldap_federation; v — vars
             (ad_base_dn, ad_org_ou).
    Returns: None.
    Fails:   SystemExit from Admin.call (including a failed sync); KeyError if a var is missing; StopIteration if
             a created mapper cannot be found again. The site groups' mapper (SITE_MAPPER) is left alone.
    Feeds:   configure_keycloak (the synced groups are what grant_role_to_group looks up)."""
    config = {
        "groups.dn": [f"OU=groups,{v['ad_org_ou']},{v['ad_base_dn']}"],
        "group.name.ldap.attribute": ["cn"],
        "group.object.classes": ["group"],
        "preserve.group.inheritance": ["false"],
        "membership.ldap.attribute": ["member"],
        "membership.attribute.type": ["DN"],
        "membership.user.ldap.attribute": ["sAMAccountName"],
        "memberof.ldap.attribute": ["memberOf"],
        "mode": ["LDAP_ONLY"],
        "user.roles.retrieve.strategy": ["GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE"],
        "drop.non.existing.groups.during.sync": ["false"],
    }
    path = f"/{q(realm)}/components?parent={ldap_id}&type={q(LDAP_MAPPER)}"
    _, mappers = kc.call("GET", path)
    mapper = next((m for m in mappers if m.get("providerId") == "group-ldap-mapper" and m.get("name") != SITE_MAPPER),
                  None)
    if mapper is None:
        kc.call("POST", f"/{q(realm)}/components", {
            "name": "LDAP Groups", "providerId": "group-ldap-mapper", "providerType": LDAP_MAPPER,
            "parentId": ldap_id, "config": config})
        _, mappers = kc.call("GET", path)
        mapper = next(m for m in mappers if m.get("providerId") == "group-ldap-mapper" and m.get("name") != SITE_MAPPER)
        step("created LDAP group mapper")
    else:
        mapper["config"] = {**mapper.get("config", {}), **config}
        kc.call("PUT", f"/{q(realm)}/components/{mapper['id']}", mapper)
    kc.call("POST", f"/{q(realm)}/user-storage/{ldap_id}/mappers/{mapper['id']}/sync?direction=fedToKeycloak")
    step("synced LDAP groups into Keycloak")
