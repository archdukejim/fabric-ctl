import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.routes.held import held
from webui.session.page_context import page_context


def _request(h, form):
    """Purpose: Scan at <site>, done at once (manual 1.10.4.40.2, 1.10.4.36): a request another site's poll answers;
             back to that site's subnet saying where its answer shows.
    Inputs:  h — the request handler (back); form — dict (site, subnet: the subnet's name, cidr).
    Returns: 303 with the outcome.
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   networks_scan_post."""
    site, name = form.get("site", ""), form.get("subnet", "")
    back = "/networks?" + urllib.parse.urlencode({"site": site, **({"subnet": name} if name else {})})
    try:
        r = actions.request_scan(site, form.get("cidr", "") or name)
    except actions.ValidationError as exc:
        return h.back(back, err=str(exc))
    return h.back(back, msg=f"Scan of {r['cidr']} requested at {r['site']}: its plan poll runs it within about 30 "
                            f"seconds; its answer shows in Scans requested at {r['site']}.")


def networks_scan_post(h, sess, parts, form):
    """Purpose: Route a POST under /networks/scan (manual 1.10.4.40.1): [] scans the chosen subnet at once and shows
             what answered; ["record"] holds a find recorded for Networks' Apply (a reservation for the MAC ARP
             saw or the one typed, or a static address: 2.1.10.50); ["request"] asks another site to scan one of
             its subnets, at once.
    Inputs:  h — the request handler (send, back, deny); sess — the session (the result page's context); parts —
             segments after /networks/scan; form — dict (subnet; or find "<ip>|<mac>", kind, mac (typed, for a
             find with none), name; or site, subnet, cidr).
    Returns: 200 the scan's result page; 303 back to /networks/scan with why a scan was refused (or a reservation
             with no MAC), or with the find held; the request's 303; 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   networks_post."""
    if parts in ([], [""]):
        try:
            result = actions.scan_subnet(form.get("subnet", ""))
        except actions.ValidationError as exc:
            return h.back("/networks/scan", err=str(exc))
        return h.send(200, views.ipam_scan(page_context(sess), actions.scannable_subnets(), result))
    if parts == ["record"]:
        ip, _, seen = str(form.get("find") or "").partition("|")
        mac = seen or str(form.get("mac") or "").strip()      # beyond a router ARP sees none (1.10.4.47)
        kind = form.get("kind", "reservation")
        if kind == "reservation" and not mac:
            return h.back("/networks/scan",
                          err="a reservation needs its MAC: type it, or record it as a static address")
        return held(h, "/networks/scan", "ipam/scan/record", {"ip": ip, "kind": kind, "mac": mac,
                                                              "name": form.get("name", "")})
    if parts == ["request"]:
        return _request(h, form)
    return h.deny(404, "Not found.")
