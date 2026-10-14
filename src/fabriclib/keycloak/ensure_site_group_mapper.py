from fabriclib.keycloak.ensure_group_mapper import LDAP_MAPPER, SITE_MAPPER as NAME
from fabriclib.keycloak.quote import q
from fabriclib.keycloak.site_bundle_grants import site_bundle_grants
from fabriclib.keycloak.site_lineage import site_lineage
from fabriclib.keycloak.step import step


def ensure_site_group_mapper(kc, realm, ldap_id, v):
    """Purpose: a second LDAP group mapper, for this site's own role groups (2.1.9.21, manual 1.6.8.2): the groups of
             site_bundle_grants (`<site>-admins`, `<site>-network-operators`, ...) in the site's OU=groups, read only
             (Keycloak never writes them), membership found through nesting (AD's LDAP_MATCHING_RULE_IN_CHAIN,
             Keycloak's LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY: a grant usually nests `<site>-admins` in the
             role's group), then synced so configure_keycloak can grant each its bundle. Since the revision of
             2026-10-13 also the console role groups of every site above this one (a role granted at a site works at
             every site below it): the search starts at the top site's OU, the filter names exactly those groups, so
             a sibling's or a site below's are never mapped.
    Inputs:  kc — Admin; realm — realm name; ldap_id — federation id from ensure_ldap_federation; v — vars
             (ad_base_dn, ad_site_ou, site_name).
    Returns: None.
    Fails:   SystemExit from Admin.call (including a failed sync); KeyError if a var is missing; ValueError from
             site_lineage (an ad_site_ou that is not the site's); StopIteration if a created mapper cannot be found
             again.
    Feeds:   configure_keycloak."""
    lineage, top = site_lineage(v)
    names = "".join(f"(cn={g})" for g, _ in site_bundle_grants(v["site_name"], lineage[1:]))
    config = {
        "groups.dn": [f"{top},{v['ad_base_dn']}"],        # the whole tree, searched below; the filter picks
        "groups.ldap.filter": [f"(|{names})"],
        "group.name.ldap.attribute": ["cn"],
        "group.object.classes": ["group"],
        "preserve.group.inheritance": ["false"],
        "ignore.missing.groups": ["true"],
        "membership.ldap.attribute": ["member"],
        "membership.attribute.type": ["DN"],
        "membership.user.ldap.attribute": ["sAMAccountName"],
        "memberof.ldap.attribute": ["memberOf"],
        "mode": ["READ_ONLY"],
        "user.roles.retrieve.strategy": ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY"],
        "drop.non.existing.groups.during.sync": ["false"],
    }
    path = f"/{q(realm)}/components?parent={ldap_id}&type={q(LDAP_MAPPER)}"
    mapper = next((m for m in kc.call("GET", path)[1] if m.get("name") == NAME), None)
    if mapper is None:
        kc.call("POST", f"/{q(realm)}/components", {
            "name": NAME, "providerId": "group-ldap-mapper", "providerType": LDAP_MAPPER, "parentId": ldap_id,
            "config": config})
        mapper = next(m for m in kc.call("GET", path)[1] if m.get("name") == NAME)
        step("created the LDAP group mapper for this site's role groups")
    else:
        mapper["config"] = {**mapper.get("config", {}), **config}
        kc.call("PUT", f"/{q(realm)}/components/{mapper['id']}", mapper)
    kc.call("POST", f"/{q(realm)}/user-storage/{ldap_id}/mappers/{mapper['id']}/sync?direction=fedToKeycloak")
    step("synced this site's role groups into Keycloak")
