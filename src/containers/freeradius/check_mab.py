from normalize_mac import normalize_mac

# Service-Type values a switch may send, by name and as FreeRADIUS may hand them over (name or number)
SERVICE_TYPES = {"Call-Check": ("Call-Check", "10")}


def check_mab(req, rules):
    """Purpose: read a MAB request (a switch asking for a device by its MAC) the way its vendor sends one (manual
             1.11.1.2): the MAC from User-Name, checked against the vendor's shape.
    Inputs:  req — dict of request attributes (first value of each, as str): User-Name, User-Password,
             Calling-Station-Id, Service-Type.
             rules — the client's "mab" rules from fabric-radius.json: {"service_type": str or None (a Service-Type
             the request must carry), "password_is_mac": bool (a User-Password, when sent, must be the same MAC)};
             None or {} for the generic rules.
    Returns: (mac, "") — mac "aa:bb:cc:dd:ee:ff" — when it is a genuine MAB request; (None, reason) otherwise, reason
             one of "not_a_MAB_request_for_this_switch" (Service-Type missing or another), "user_name_is_not_a_MAC",
             "user_name_is_not_the_calling_MAC", "password_is_not_the_MAC".
    Fails:   never.
    Feeds:   fabric_radius.authorize (MAB); tests/freeradius/check_mab_test.py.
    """
    rules = rules or {}
    wanted = rules.get("service_type")
    if wanted and str(req.get("Service-Type", "")) not in SERVICE_TYPES.get(wanted, (wanted,)):
        return None, "not_a_MAB_request_for_this_switch"
    mac = normalize_mac(req.get("User-Name"))
    if not mac:
        return None, "user_name_is_not_a_MAC"
    station = normalize_mac(req.get("Calling-Station-Id"))
    if req.get("Calling-Station-Id") and station != mac:
        return None, "user_name_is_not_the_calling_MAC"
    if rules.get("password_is_mac") and req.get("User-Password") is not None \
            and normalize_mac(req.get("User-Password")) != mac:
        return None, "password_is_not_the_MAC"
    return mac, ""
