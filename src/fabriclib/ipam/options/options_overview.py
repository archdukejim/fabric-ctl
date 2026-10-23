from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.option_codes import CATALOGUE
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.options.effective_options import effective_options
from fabriclib.ipam.options.settings_options import settings_options
from fabriclib.ipam.read_plan import read_plan


def options_overview(v, site="", target="", secrets=None, container="samba"):
    """Purpose: what the options page shows (manual 1.10.4.24.6): the domain's and the site's option sets, each served
             subnet and reservation with its own options and netboot preset, the standard option names, and, given
             a target, its effective options with their sources (effective_options). Read-only: any site's plan
             reads from any site (who may change it is the grants' networks options right, 1.6.13.12).
    Inputs:  v — fabric vars (site_name, dhcp); site — the site shown ("" this site); target — "", "site",
             "subnet:<name or network>" or "address:<ip>"; secrets — fabric's secrets (default loaded by
             read_plan); container — the DC's container.
    Returns: {"site", "here", "domain" (set or None), "site_options" (set), "settings" (what vars.yaml still
             carries, or None), "subnets": [{"name", "cidr", "vlan", "id", "dhcp", "options", "netboot",
             "reservations": [{"ip", "name", "mac", "options", "netboot"}]}], "catalogue": [{"code", "name"}],
             "effective": effective_options' result or None}.
    Fails:   ValidationError: a bad target; what read_plan ("no such site") or effective_options refuses.
    Feeds:   run_option_command (option show, netboot show), agent GET /v1/ipam/options/<site>[/<target>]."""
    here = v["site_name"]
    site = site or here
    plan = site_plan(read_plan(v, secrets, of=site, container=container), site)
    settings = settings_options(v) if site == here else None
    effective = None
    if target:
        kind, _, name = target.partition(":")
        if kind == "site" and not name:
            effective = effective_options(plan, "site", "", v, settings)
        elif kind in ("subnet", "address") and name:
            effective = effective_options(plan, kind, name, v if site == here else None, settings)
        else:
            raise ValidationError("target: site, subnet:<name> or address:<ip>")
    subnets = [{"name": s["name"], "cidr": s["cidr"], "vlan": s.get("vlan"), "id": s.get("id"),
                "dhcp": bool(s.get("dhcp")), "options": s.get("options") or [], "netboot": s.get("netboot"),
                "reservations": [{"ip": a["ip"], "name": a.get("name", ""), "mac": a.get("mac", ""),
                                  "options": a.get("options") or [], "netboot": a.get("netboot")}
                                 for a in s.get("addresses") or [] if a["kind"] == "reservation"]}
               for s in plan["subnets"]]
    return {"site": site, "here": here, "domain": plan["domain_options"], "site_options": plan["site_options"],
            "settings": settings, "subnets": subnets,
            "catalogue": [{"code": c, "name": n} for c, n in sorted(CATALOGUE.items())], "effective": effective}
