from fabriclib.federation.common.load_registry import load_registry
from fabriclib.rbac.permissions import SITE_ROLE_BUNDLES

# the site's AD role groups and host admins (2.1.9.13, 2.1.6.37), as the DC's site_roles names them
AD_ROLES = ("ou-admins", "machine-admins", "gpo-admins", "windows-admins", "fabric-admins")


def granted_from_above(v, group, registry=None):
    """Purpose: whether a group's members are granted only from a site above (2.1.9.21, revised 2026-10-13): at a site
             with an upstream, its own `<site>-admins`, its AD role groups, `<site>-fabric-admins` and its console role
             groups. AD refuses this site's agent those memberships; this says so first, in words.
    Inputs:  v — fabric vars (site_name); group — the group's name; registry — load_registry()'s dict (default: read
             it).
    Returns: bool; False at the top (no upstream: Central IT grants there) and for any other group.
    Fails:   yaml/OSError from load_registry for a malformed registry.
    Feeds:   directory/set_person_group."""
    registry = registry if registry is not None else load_registry()
    if not registry.get("upstream"):
        return False
    site = v["site_name"].lower()
    return group.lower() in {f"{site}-{role}" for role in list(AD_ROLES) + list(SITE_ROLE_BUNDLES)}
