from fabriclib.ipam.common.vlan_refs import vlan_ref
from fabriclib.ipam.rules.constants import DEFAULT_RULES, SERVICES


def seed_rules(plan, host_vlan=None):
    """Purpose: the rules a site has before any are kept (manual 1.10.4.48.7, decision 2.1.10.59): a fresh site's
             one rule; a site upgraded with VLANs in its plan, rules that keep what each reached before (2.1.10.4):
             the host's VLAN everything, a guest VLAN DHCP, DNS and NTP, any other VLAN with a served subnet every
             service but SSH, a VLAN with no served subnet nothing.
    Inputs:  plan — the site's plan (vlans with "access", subnets with "dhcp"), or None; host_vlan — the host's
             VLAN's reference when known (rule_networks), left out: the first rule already allows it everything.
    Returns: list of rules ({"from", "service", "action"}), the default's first.
    Fails:   never.
    Feeds:   effective_rules, ipam/rules/seed_site_rules."""
    rules = [dict(r) for r in DEFAULT_RULES]
    plan = plan or {}
    served = {vlan_ref({"id": s.get("vlan"), "location": s.get("location") or ""})
              for s in plan.get("subnets") or [] if s.get("dhcp")}
    for vlan in plan.get("vlans") or []:
        ref = vlan_ref(vlan)
        if ref not in served or ref == host_vlan:
            continue
        if str(vlan.get("access") or "full").lower() == "guest":
            rules += [{"from": ref, "service": s, "action": "allow"} for s in ("dhcp", "dns", "ntp")]
        else:
            rules += [{"from": ref, "service": s, "action": "allow"} for s in SERVICES if s != "ssh"]
    return rules
