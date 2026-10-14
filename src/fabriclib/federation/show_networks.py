from fabriclib.federation.common.sites_shown import sites_shown
from fabriclib.federation.common.visible_plan import visible_plan
from fabriclib.federation.network_conflicts import network_conflicts
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.federation.site_networks import site_networks


def show_networks(v):
    """Purpose: print the address plan across sites for `fabricctl federation networks` (manual 1.10.2.6): site →
                network → VLAN → kind → notes, then every overlap between sites
             (with the reason when one was given); only the sites this install shows (2.1.9.22: the top every site,
             a site itself and the sites below it; an overlap with a site not shown is counted, never named).
    Inputs:  v — fabric vars: site_name, lan_cidr, dhcp (this site's networks are shown from its settings until
             convergence has written them to the domain).
    Returns: the number of overlaps without a reason (0: none), those with a site not shown included.
    Fails:   ValidationError from read_address_plan (the DC not reachable).
    Feeds:   federation/run_federation_command (`networks`)."""
    full = read_address_plan(v)
    shown = visible_plan(full, sites_shown(v))
    plan = shown["plan"]
    site = v.get("site_name") or ""
    if not any(p["site"] == site for p in plan):
        plan += [{**n, "site": site, "unpublished": True} for n in site_networks(v)]
    if not plan:
        print("no networks yet")
        return 0
    print(f"{'site':<16} {'network':<20} {'name':<16} {'VLAN':<6} {'kind':<6} notes")
    for p in sorted(plan, key=lambda n: (n["site"], n["cidr"])):
        print(f"{p['site']:<16} {p['cidr']:<20} {p.get('name', ''):<16} {str(p.get('vlan') or '-'):<6} "
              f"{p.get('kind', ''):<6} {p.get('notes', '')}" + ("  (not in the root's plan yet)"
                                                                 if p.get("unpublished") else ""))
    seen, unallowed = set(), 0
    for s in sorted({p["site"] for p in plan}):
        for c in network_conflicts([p for p in plan if p["site"] == s], plan, s):     # among the sites shown
            pair = tuple(sorted([(s, c["cidr"]), (c["other_site"], c["other_cidr"])]))
            if pair in seen:
                continue
            seen.add(pair)
            unallowed += not c["allowed"]
            print(f"OVERLAP {s} {c['cidr']} and {c['other_site']} {c['other_cidr']}"
                  + (f" (allowed: {c['allowed']})" if c["allowed"] else ""))
    if shown["hidden_overlaps"]:
        print(f"OVERLAP {shown['hidden_overlaps']} with a site this one does not show (ask the top site)")
    return unallowed + shown["hidden_overlaps"]
