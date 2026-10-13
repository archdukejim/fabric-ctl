import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.plan_cache import load_plan_cache, save_plan_cache
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.merge_option_sets import merge_option_sets
from fabriclib.ipam.options.plan_digest import plan_digest
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


def _globals(final_vars, d, rendered):
    """Purpose: the site's Kea global level from the plan's option sets with, above them, what the settings still carry
             (an install whose options have not moved into the plan yet, manual 1.10.4.24.4).
    Inputs:  final_vars — rendered settings (dhcp changed in place); d — the settings' dhcp block as it was;
             rendered — plan_to_dhcp's result (options, option_defs, client_classes).
    Returns: None.
    Fails:   never.
    Feeds:   load_address_plan."""
    settings = {k: d.get(k) or [] for k in ("options", "option_defs", "client_classes")}
    plan_level = {k: rendered.get(k) or [] for k in ("options", "option_defs", "client_classes")}
    netboot = [c for c in plan_level["client_classes"] if c["name"].startswith("fabric-nb-")]
    plan_level["client_classes"] = [c for c in plan_level["client_classes"] if c not in netboot]
    merged = merge_option_sets(plan_level, settings)
    merged["client_classes"] += netboot          # after every class they may name (Kea reads them in order)
    dhcp = final_vars["dhcp"]
    for key, value in merged.items():
        if value:
            dhcp[key] = value
        else:
            dhcp.pop(key, None)


def load_address_plan(final_vars, secrets, container="samba", digest=None):
    """Purpose: at every apply, the site's subnets and static names from its plan in the domain (manual 1.10.4.4,
             1.10.4.14): read from the DC as the site's agent and kept; a DC that does not answer leaves the apply on
             the plan last read (its last rendering). And the global options, definitions and classes: the
             organisation's and the site's sets (2.1.10.23), the netboot classes (2.1.10.25), and above them what the
             settings still carry (1.10.4.24.4). While the settings still carry `dhcp.subnets` (an install not yet
             upgraded: convergence moves them, move_subnets_to_plan; a site with a read-only DC, 2.1.10.19) only the
             option sets are read, and nothing is kept or required.
    Inputs:  final_vars — rendered settings (site_name, install_kea, dhcp, dns), changed in place: dhcp.subnets from
             the plan, dhcp.options / option_defs / client_classes, dns.dynamic_zone_var.A with the plan's published
             addresses; secrets — fabric's secrets (ad_agent_password); container — the DC's container; digest — a dict
             filled with what DNS is rendered from ({"dns": plan_digest's}) when DNS is rendered from this too (an
             apply, a zone change), for the caller to keep for the plan poll (<config>/plan-dns.json, manual
             1.10.4.26) once BIND took it (2.3.10.5.6); None (the poll) leaves it.
    Returns: list of str to show (where the plan came from, names left out).
    Fails:   ValidationError when DHCP is on, the subnets live in the plan and no plan can be had (the DC not
             answering and none kept): Kea is then left as it was rendered. OSError writing the kept copy.
    Feeds:   deploy/check_rendered (an apply, before check_settings), ipam/options/render_kea (the plan poll)."""
    d = dict(final_vars.get("dhcp") or {})
    if not final_vars.get("site_name"):
        return []
    if "subnets" in d:                    # not upgraded yet: the subnets stay the settings', the option sets join them
        if not final_vars.get("install_kea"):
            return []
        try:
            read = read_plan(final_vars, secrets, of=final_vars["site_name"], container=container)
        except (ValidationError, OSError, subprocess.TimeoutExpired):
            return []
        plan = site_plan(read, final_vars["site_name"])
        final_vars["dhcp"] = d
        _globals(final_vars, d, merge_option_sets(plan.get("org_options"), plan.get("site_options")))
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
    _globals(final_vars, d, rendered)
    if digest is not None:              # kept by the caller once BIND took it, never before (2.3.10.5.6)
        digest["dns"] = plan_digest(rendered)["dns"]
    lines += [f"address plan: {n} keeps the settings' record" for n in _add_records(final_vars, rendered["records"])]
    return lines
