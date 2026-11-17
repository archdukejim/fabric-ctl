from fabriclib.ipam.common.vlan_refs import vlan_ref
from fabriclib.ipam.rules.constants import ANY, FABRIC, SERVICES


def _row(allowed):
    """Purpose: one network's row: every service, allowed or not.
    Inputs:  allowed — set of the services allowed.
    Returns: {service: "allow" | "deny"} in SERVICES' order.
    Fails:   never.
    Feeds:   access_table."""
    return {s: "allow" if s in allowed else "deny" for s in SERVICES}


def access_table(plan, host_vlan):
    """Purpose: what each network of a site reaches (manual 1.10.4.48.10, decision 2.1.10.63): every VLAN of its plan,
             the other sites (`fabric`) and outside (`any`), each with every service allowed or denied. The rows kept
             on the site's record win; a network without one has its default (the host's VLAN everything, the rest
             nothing). While nothing is kept, a site with VLANs has what it reached before 0.10.0 (2.1.10.59): each
             VLAN with a served subnet every service but SSH.
    Inputs:  plan — the site's plan (site_plan's: vlans, subnets, rules (the rows kept: [{"net", service: action}]),
             rules_kept), or None; host_vlan — the host's VLAN's reference (rule_networks), or None.
    Returns: {network: {service: action}}: the VLANs in the plan's order, then "fabric", then "any".
    Fails:   never (a kept row for a network the plan no longer has, or with an unknown service, is ignored).
    Feeds:   service_sources, change_access_rows, access_view, show_access, seed_site_access."""
    plan = plan or {}
    refs = [vlan_ref(x) for x in plan.get("vlans") or []]
    table = {ref: _row(set(SERVICES) if ref == host_vlan else set()) for ref in refs}
    table[FABRIC] = _row(set())
    table[ANY] = _row(set())
    if plan.get("rules_kept"):
        for row in plan.get("rules") or []:
            net = str((row or {}).get("net") or "")
            if net in table:
                table[net] = {s: "allow" if row.get(s) == "allow" else "deny" for s in SERVICES}
        return table
    served = {vlan_ref({"id": s.get("vlan"), "location": s.get("location") or ""})
              for s in plan.get("subnets") or [] if s.get("dhcp")}
    for ref in refs:
        if ref in served and ref != host_vlan:
            table[ref] = _row({s for s in SERVICES if s != "ssh"})
    return table
