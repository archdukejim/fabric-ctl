import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.plan_cache import load_plan_cache, save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.plan_to_dhcp import plan_to_dhcp
from fabriclib.ipam.read_plan import read_plan


def _add_records(final_vars, records):
    """Purpose: the plan's static addresses published in DNS as A records of the site's zone (manual 1.10.4.5): a name
             the settings already hold in that zone keeps the settings' record.
    Inputs:  final_vars — rendered settings (dns, changed in place); records — plan_to_dhcp's records.
    Returns: list of str, the names left out (already in the zone with another address).
    Fails:   never.
    Feeds:   load_address_plan."""
    if not records:
        return []
    dns = final_vars.setdefault("dns", {}) or {}
    final_vars["dns"] = dns
    zone = dns.setdefault("dynamic_zone_var", {}) or {}
    dns["dynamic_zone_var"] = zone
    have = {str(r.get("name") or "").lower(): str(r.get("ip")) for r in zone.get("A") or []}
    skipped = []
    zone["A"] = list(zone.get("A") or [])
    for r in records:
        if r["name"] in have:
            if have[r["name"]] != r["ip"]:
                skipped.append(f"{r['name']} ({r['ip']}: the settings name it {have[r['name']]})")
            continue
        zone["A"].append({"name": r["name"], "ip": r["ip"]})
    return skipped


def load_address_plan(final_vars, secrets, container="samba"):
    """Purpose: at every apply, the site's subnets and static names from its plan in the domain (manual 1.10.4.4,
             1.10.4.14): read from the DC as the site's agent and kept; a DC that does not answer leaves the apply on
             the plan last read (its last rendering). Nothing is read while the settings still carry `dhcp.subnets`
             (an install not yet upgraded: convergence moves them, move_subnets_to_plan).
    Inputs:  final_vars — rendered settings (site_name, install_kea, dhcp, dns), changed in place: dhcp.subnets from
             the plan, dns.dynamic_zone_var.A with the plan's published addresses; secrets — fabric's secrets
             (ad_agent_password); container — the DC's container.
    Returns: list of str to show (where the plan came from, names left out); [] when the settings carry the subnets.
    Fails:   ValidationError when DHCP is on and no plan can be had (the DC not answering and none kept): Kea is then
             left as it was rendered. OSError writing the kept copy.
    Feeds:   deploy/apply_deployment (before check_settings)."""
    d = dict(final_vars.get("dhcp") or {})
    if "subnets" in d or not final_vars.get("site_name"):
        return []
    lines = []
    try:
        read = read_plan(final_vars, secrets, of=final_vars["site_name"], container=container)
    except (ValidationError, OSError, subprocess.TimeoutExpired) as e:     # the DC not answering
        plan = load_plan_cache()
        if plan is None:
            if final_vars.get("install_kea"):
                raise ValidationError(f"the address plan could not be read from the domain ({e}) and no earlier copy "
                                      "is kept: start the samba service, then apply again")
            return []
        lines.append(f"address plan: the domain did not answer ({e}); rendering the plan read {plan.get('read')}")
    else:
        plan = site_plan(read, final_vars["site_name"])
        save_plan_cache(plan)
    rendered = plan_to_dhcp(plan)
    final_vars["dhcp"] = {**d, "subnets": rendered["subnets"]}
    lines += [f"address plan: {n} keeps the settings' record" for n in _add_records(final_vars, rendered["records"])]
    return lines
