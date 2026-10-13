from fabriclib.radius.nas.nas_profile import nas_profile
from fabriclib.radius.nas.profiles import DEFAULT_VENDOR


def policy_clients(clients):
    """Purpose: What FreeRADIUS's policy must know about each RADIUS client: its vendor and the profile's policy part
             (how a MAB request looks, which VLAN attributes to send), keyed by the client's name (its shortname in
             clients.conf, which the sites hand the policy as Tmp-String-3).
    Inputs:  clients — radius_clients as normalize_radius_clients returns them (each with a vendor; none: generic).
    Returns: {name: {"vendor", "transport", "mab": {...}, "vlan": "rfc3580"}}.
    Fails:   ValidationError from nas_profile for an unknown vendor.
    Feeds:   templates/freeradius/config/fabric-radius.json.j2 (through deploy_freeradius); tests/freeradius.
    """
    out = {}
    for c in clients or []:
        profile = nas_profile(c.get("vendor") or DEFAULT_VENDOR)
        out[c["name"]] = {"vendor": profile["vendor"], "transport": c.get("transport", "udp"),
                          **profile["policy"]}
    return out
