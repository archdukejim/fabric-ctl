from fabriclib.rbac.permissions import SITE_ROLE_BUNDLES


def site_bundle_grants(site):
    """Purpose: which of a site's own groups this site's Keycloak gives which bundle (2.1.9.21, manual 1.6.8.2;
             1.9.3.1's decision F4 "a site's Keycloak maps global groups and its own site's groups only"):
             `<site>-admins` the site helpdesk, and each console role a site above may grant
             (`<site>-network-operators`, ...) its bundle.
             Never another site's groups: a role granted at one site gives nothing at any other.
    Inputs:  site — str, this site's name.
    Returns: list of (group name, bundle role name), in SITE_ROLE_BUNDLES' order.
    Fails:   never.
    Feeds:   configure_keycloak (grant_role_to_group), ensure_site_group_mapper (which groups to sync)."""
    return [(f"{site}-{role}", bundle) for role, bundle in SITE_ROLE_BUNDLES.items()]
