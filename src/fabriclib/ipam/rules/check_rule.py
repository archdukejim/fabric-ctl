from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.vlan_refs import parse_vlan_ref, vlan_ref
from fabriclib.ipam.rules.constants import ACTIONS, ANY, HOST, SERVICES


def check_rule(source, service, action, plan):
    """Purpose: one access rule as typed, checked and written the way it is kept (manual 1.10.4.48.1, 1.10.4.48.5).
    Inputs:  source — "host", "any", or a VLAN of the site ("10", "10@branch"); service — one of constants.SERVICES
             or "any"; action — "allow" or "deny"; plan — the site's plan (vlans).
    Returns: {"from", "service", "action"}, lower case, the VLAN as vlan_ref writes it.
    Fails:   ValidationError naming what is wrong: a source that is not host, any or a VLAN of this site's plan; a
             service or an action that is not one.
    Feeds:   add_rule."""
    src = str(source or "").strip().lower()
    if src not in (HOST, ANY):
        vid, location = parse_vlan_ref(src)
        src = vlan_ref({"id": vid, "location": location})
        if src not in {vlan_ref(x) for x in (plan or {}).get("vlans") or []}:
            raise ValidationError(f"from {source}: the site has no VLAN {src}: add it first (ipam vlan add), or "
                                  f"use host or any")
    svc = str(service or "").strip().lower()
    if svc not in SERVICES and svc != ANY:
        raise ValidationError(f"service {service!r}: one of {', '.join([*SERVICES, ANY])}")
    act = str(action or "").strip().lower()
    if act not in ACTIONS:
        raise ValidationError(f"{action!r}: allow or deny")
    return {"from": src, "service": svc, "action": act}
