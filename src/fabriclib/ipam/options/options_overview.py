from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.common.option_codes import CATALOGUE
from fabriclib.ipam.options.effective_options import effective_options
from fabriclib.ipam.options.settings_options import settings_options
from fabriclib.ipam.read_plan import read_plan


def options_overview(v, site="", target="", secrets=None, container="samba", root=None):
    """Purpose: what the options page shows (manual 1.10.4.24.6): the organisation's and the site's option sets, each
             served subnet and reservation with its own options and netboot preset, whether this site may edit the
             organisation's set, the standard option names, and, given a target, its effective options with their
             sources (effective_options). Read-only.
    Inputs:  v — fabric vars (site_name, dhcp); site — the site shown ("" this site; another only from the top site);
             target — "", "site", "subnet:<name or network>" or "address:<ip>"; secrets — fabric's secrets (default
             loaded by read_plan); container — the DC's container; root — whether this is the top site (None: the
             federation registry says).
    Returns: {"site", "here", "root", "org" (set or None), "site_options" (set), "settings" (what vars.yaml still
             carries, or None), "org_editors", "org_editable" (bool), "subnets": [{"name", "cidr", "vlan", "id",
             "options", "netboot", "reservations": [{"ip", "name", "mac", "options", "netboot"}]}], "catalogue":
             [{"code", "name"}], "effective": effective_options' result or None}.
    Fails:   ValidationError: another site's from a site that is not the top; a bad target; what read_plan or
             effective_options refuses.
    Feeds:   agent routes GET /v1/ipam/options/<site> and /v1/ipam/options/<site>/<target>."""
    here = v["site_name"]
    site = site or here
    root = is_root_site() if root is None else root
    if site != here and not root:
        raise ValidationError("a site's DHCP options are shown at that site, or at the top site")
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
    return {"site": site, "here": here, "root": root, "org": plan["org_options"], "site_options": plan["site_options"],
            "settings": settings, "org_editors": plan["org_editors"],
            "org_editable": root or here in plan["org_editors"], "subnets": subnets,
            "catalogue": [{"code": c, "name": n} for c, n in sorted(CATALOGUE.items())], "effective": effective}
