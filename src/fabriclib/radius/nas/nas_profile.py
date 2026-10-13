from fabriclib.common.errors import ValidationError
from fabriclib.radius.nas.profiles import PROFILES, VENDORS


def nas_profile(vendor):
    """Purpose: The profile of a RADIUS client's vendor (what FreeRADIUS returns, MAB's shape, RadSec, CoA).
    Inputs:  vendor — "unifi", "cisco" or "generic" (case and spaces ignored).
    Returns: the profile dict from profiles.PROFILES, with "vendor" added (a copy: callers may not change the table).
    Fails:   ValidationError "vendor must be one of unifi, cisco, generic" for anything else (fail loudly: an
             unknown vendor never falls back silently).
    Feeds:   normalize_radius_clients, policy_clients, coa_session, radius_overview, radius_guides.
    """
    key = str(vendor or "").strip().lower()
    if key not in PROFILES:
        raise ValidationError("vendor must be one of " + ", ".join(VENDORS))
    return dict(PROFILES[key], vendor=key)
