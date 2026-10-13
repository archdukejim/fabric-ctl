from fabriclib.common.errors import ValidationError
from fabriclib.dhcp.list_leases import list_leases
from fabriclib.ipam.common.plan_holds_subnets import plan_holds_subnets
from fabriclib.ipam.planned_subnets import planned_subnets
from fabriclib.system.host_networks import host_networks


def dhcp_overview(v, networks=None):
    """Purpose: What the Kea tab and `fabricctl dhcp` show: whether DHCP is on, its interfaces, subnets (pools, router,
             reservations), lease time, the DHCP subzone and the live leases. Read-only.
    Inputs:  v — the vars dict (install_kea, dhcp, domain; its subnets, or the plan's once they live there:
             planned_subnets, manual 1.10.4.14); networks — host_networks() (None: read this host's). Asks
             Kea's control socket when DHCP is on.
    Returns: {"enabled", "interfaces", "subnets" (with id, name, vlan, notes, options as stored), "lease_time",
             "ddns_zone" ("" when DDNS is off), "options" (the admin's, every subnet), "overrides" (names of the
             options fabric sets itself that the admin replaced: domain-name-servers, ntp-servers, domain-name,
             domain-search, routers — shown so a replaced default is never a surprise), "option_defs",
             "client_classes", "leases" (see list_leases), "leases_error" (why leases could not be read, else ""),
             "host_interfaces" ([{"name", "address", "network"}]: what DHCP could serve, Docker's own left out),
             "has_settings" (bool: subnets kept from before, so turning DHCP on resumes them; manual 1.10.3.5),
             "in_plan" (bool: the subnets live in the address plan, so the Kea tab links to the Networks tab
             instead of editing them, 1.10.4.21)}.
    Fails:   never for Kea problems — a ValidationError from list_leases goes into leases_error; other errors propagate.
    Feeds:   agent route GET /v1/dhcp (fabric-agent, src/agent/, called by the web UI); run_dhcp_command
             (status, leases).
    """
    d = v.get("dhcp") or {}
    out = {"enabled": bool(v.get("install_kea")), "interfaces": d.get("interfaces") or [],
           "subnets": planned_subnets(v), "lease_time": d.get("lease_time", 86400),
           "ddns_zone": f"{d.get('ddns_subdomain', 'dhcp')}.{v.get('domain', '')}" if d.get("ddns", True) else "",
           "options": d.get("options") or [], "option_defs": d.get("option_defs") or [],
           "client_classes": d.get("client_classes") or [], "leases": [], "leases_error": "",
           "has_settings": bool(planned_subnets(v)), "in_plan": plan_holds_subnets(v)}
    nets = host_networks() if networks is None else networks
    out["host_interfaces"] = [{"name": name, "address": str(a.ip), "network": str(a.network)}
                              for name, addrs in sorted(nets.items())
                              if name != "lo" and not name.startswith(("docker", "br-", "veth")) for a in addrs]
    own = {"domain-name-servers", "ntp-servers", "domain-name", "domain-search", "routers"}
    out["overrides"] = sorted({o.get("name") for o in out["options"] if o.get("name") in own}
                              | {f"routers ({s.get('name', s.get('subnet'))})" for s in out["subnets"]
                                 if any(o.get("name") == "routers" for o in s.get("options") or [])})
    if out["enabled"]:
        try:
            out["leases"] = list_leases(v)
        except ValidationError as exc:
            out["leases_error"] = str(exc)
    return out
