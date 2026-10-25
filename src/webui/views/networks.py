from webui.views.render_page import render_page

VIEWS = ("new-vlan", "number")               # the forms on their own page (Add VLAN, the site's number)


def _hits(overview, q):
    """Purpose: The address table rows of every subnet of the site that match a search: part of an address, a name or
             a MAC (- or :, any case); free runs are left out.
    Inputs:  overview — networks_overview's dict; q — the search as typed.
    Returns: list of (subnet name, row).
    Fails:   never.
    Feeds:   networks."""
    want = q.strip().lower()
    mac = want.replace("-", ":")
    out = []
    for vlan in overview.get("vlans") or []:
        for sub in vlan.get("subnets") or []:
            for r in sub.get("rows") or []:
                if r.get("kind") == "free":
                    continue
                if (want in r.get("ip", "") or want in (r.get("name") or "").lower()
                        or (mac and mac in (r.get("mac") or "").lower())):
                    out.append((sub["name"], r))
    return out


def _shown(overview, query):
    """Purpose: The VLAN, subnet and address the page's address names, each looked up in the site shown.
    Inputs:  overview — networks_overview's dict; query — dict: vlan (an ID), subnet (a name), address (an IP, with
             subnet).
    Returns: (vlan, subnet, row): each a dict or None.
    Fails:   LookupError saying what is not there ("no subnet x in lab's plan"): the route answers 404 (2.1.8.16).
    Feeds:   networks."""
    site, vlans = overview.get("site", ""), overview.get("vlans") or []
    if query.get("subnet"):
        found = next(((v, s) for v in vlans for s in v.get("subnets") or [] if s["name"] == query["subnet"]), None)
        if found is None:
            raise LookupError(f"no subnet {query['subnet']} in {site}'s plan")
        if not query.get("address"):
            return found[0], found[1], None
        row = next((r for r in found[1].get("rows") or [] if r.get("ip") == query["address"]
                    and r.get("kind") != "free"), None)
        if row is None:
            raise LookupError(f"no address {query['address']} recorded or leased in {query['subnet']}")
        return found[0], found[1], row
    if query.get("vlan"):
        vlan = next((v for v in vlans if str(v.get("ref", v.get("id"))) == str(query["vlan"])), None)
        if vlan is None:
            raise LookupError(f"no VLAN {query['vlan']} in {site}'s plan")
        return vlan, None, None
    return None, None, None


def networks(ctx, overview, query):
    """Purpose: DHCP · Networks (manual 1.10.4.40.1): a site's plan as a list (the sites, Sync now, the scans
             requested there, its VLANs with each subnet's bar map), a VLAN's page, a subnet's page (its bar, facts,
             ranges, address table, options and sources, and its forms in sections), an address's page, Add VLAN or
             the site's number on their own page, or a search's matching rows. The forms show only with dhcp:write.
    Inputs:  ctx — page context; overview — networks_overview's dict; query — dict: view (new-vlan, number), vlan,
             subnet, address, q.
    Returns: HTML str.
    Fails:   LookupError for a VLAN, subnet or address that is not there (_shown); Jinja2 errors propagate.
    Feeds:   src/webui/routes/networks_page (/networks); the dev preview."""
    for v in overview.get("vlans") or []:      # how the page names each VLAN (networks_view; manual 1.10.4.46)
        v.setdefault("location", "")
        v.setdefault("ref", f"{v.get('id')}@{v['location']}" if v["location"] else str(v.get("id")))
        v.setdefault("label", f"VLAN {v.get('id')}" + (f" at {v['location']}" if v["location"] else ""))
    vlan, subnet, row = _shown(overview, query)
    q = query.get("q", "")
    return render_page("networks", ctx=ctx, page="/networks", n=overview, view=query.get("view") if query.get("view")
                       in VIEWS and not (vlan or subnet) else "", vlan=vlan, s=subnet, row=row, q=q,
                       hits=_hits(overview, q) if q.strip() else None)
