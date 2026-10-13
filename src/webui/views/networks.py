from webui.views.render_page import render_page


def _hits(overview, q):
    """Purpose: the address table rows of every subnet of the site that match a search: part of an address, a name or
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


def networks(ctx, overview, subnet="", q="", msg="", err=""):
    """Purpose: The Networks tab (manual 1.10.4.9, 1.10.4.21): the sites this console shows with their numbers, the
             shown site's VLANs with each subnet's bar map and counts; one subnet's address table (every address:
             the plan's, leases beside them, unrecorded leases, free runs), its options with their sources and the
             "provided by fabric" pill, and its forms; or a search's matching rows. The forms show only with
             dhcp:write.
    Inputs:  ctx — page context; overview — networks_overview's dict; subnet — the subnet to open (its name, ""
             none); q — a search ("" none); msg, err — flash texts.
    Returns: HTML str.
    Fails:   Jinja2 errors propagate (e.g. UndefinedError when the template reads an attribute of a value the caller
             left out).
    Feeds:   src/webui/routes/networks_page (/networks); the dev preview."""
    found = None
    for vlan in overview.get("vlans") or []:
        for sub in vlan.get("subnets") or []:
            if subnet and sub["name"] == subnet:
                found = (vlan, sub)
    hits = _hits(overview, q) if q.strip() else None
    return render_page("networks", ctx=ctx, tab="networks", n=overview, open=found, q=q, hits=hits, msg=msg,
                       err=err)
