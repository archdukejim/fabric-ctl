import ipaddress

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.vlan_refs import parse_vlan_ref, vlan_ref
from fabriclib.ipam.rules.constants import ACTIONS, ANY, FABRIC, HOST, SERVICES, SITE


def _subnet(text, plan):
    """Purpose: a subnet of the site's plan named by its network, as the plan writes it.
    Inputs:  text — what was typed ("10.1.20.0/24"); plan — the site's plan (subnets).
    Returns: the plan's own CIDR str.
    Fails:   ValidationError: not a network, or not a subnet of this site's plan.
    Feeds:   check_rule."""
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationError(f"from {text}: not a network: a subnet of the site's plan, as 10.1.20.0/24")
    for s in (plan or {}).get("subnets") or []:
        try:
            if s.get("cidr") and ipaddress.ip_network(s["cidr"], strict=False) == net:
                return s["cidr"]
        except ValueError:
            continue
    raise ValidationError(f"from {text}: not a subnet of the site's plan: add it first (ipam subnet add), or use its "
                          f"VLAN, site, fabric or any")


def check_rule(source, service, action, plan):
    """Purpose: one access rule as typed, checked and written the way it is kept (manual 1.10.4.48.1, 1.10.4.48.5,
             decision 2.1.10.62).
    Inputs:  source — "host", "site", "fabric", "any", a VLAN of the site ("10", "10@branch") or a subnet of its plan
             ("10.1.20.0/24"); service — one of constants.SERVICES or "any"; action — "allow" or "deny"; plan — the
             site's plan (vlans, subnets).
    Returns: {"from", "service", "action"}, lower case, a VLAN as vlan_ref writes it, a subnet as the plan does.
    Fails:   ValidationError naming what is wrong: a source that is none of those; a service or an action that is
             not one.
    Feeds:   add_rule, set_rule."""
    src = str(source or "").strip().lower()
    if "/" in src:
        src = _subnet(src, plan)
    elif src not in (HOST, SITE, FABRIC, ANY):
        vid, location = parse_vlan_ref(src)
        src = vlan_ref({"id": vid, "location": location})
        if src not in {vlan_ref(x) for x in (plan or {}).get("vlans") or []}:
            raise ValidationError(f"from {source}: the site has no VLAN {src}: add it first (ipam vlan add), or "
                                  f"use host, site, fabric, any or a subnet")
    svc = str(service or "").strip().lower()
    if svc not in SERVICES and svc != ANY:
        raise ValidationError(f"service {service!r}: one of {', '.join([*SERVICES, ANY])}")
    act = str(action or "").strip().lower()
    if act not in ACTIONS:
        raise ValidationError(f"{action!r}: allow or deny")
    return {"from": src, "service": svc, "action": act}
