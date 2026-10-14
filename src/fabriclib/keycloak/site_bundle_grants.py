from fabriclib.rbac.permissions import SITE_ROLE_BUNDLES


def site_bundle_grants(site, above=()):
    """Purpose: which site groups this site's Keycloak gives which bundle (2.1.9.21, manual 1.6.8.2; 1.9.3.1's
             decision F4 "a site's Keycloak maps global groups and its own site's groups"): `<site>-admins` the site
             helpdesk, and each console role a site above may grant (`<site>-network-operators`, ...) its bundle; and,
             since the revision of 2026-10-13 (the owner's choice (b) of 2.3.9.2.5), the console role groups of every
             site above it too, so a role granted at a site works at every site below it. Never a sibling's or a site
             below's groups, and never an ancestor's `<site>-admins` (a site's helpdesk is its own site's, "3 b").
    Inputs:  site — str, this site's name; above — the sites above it, nearest first (site_lineage).
    Returns: list of (group name, bundle role name): this site's in SITE_ROLE_BUNDLES' order, then each ancestor's.
    Fails:   never.
    Feeds:   configure_keycloak (grant_role_to_group), ensure_site_group_mapper (which groups to sync)."""
    own = [(f"{site}-{role}", bundle) for role, bundle in SITE_ROLE_BUNDLES.items()]
    return own + [(f"{a}-{role}", bundle) for a in above for role, bundle in SITE_ROLE_BUNDLES.items()
                  if role != "admins"]
