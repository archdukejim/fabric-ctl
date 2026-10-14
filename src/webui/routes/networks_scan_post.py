import urllib.parse

from webui import agentclient as actions
from webui import views
from webui.routes.saved_and_applied import saved_and_applied
from webui.session.page_context import page_context


def _record(form):
    """Purpose: record one address the scan found, through the agent (a reservation for its MAC, or static).
    Inputs:  form — dict with ip, kind, mac, name.
    Returns: (agent result, message).
    Fails:   agent errors propagate (saved_and_applied handles ValidationError).
    Feeds:   networks_scan_post."""
    res = actions.record_found_address(form.get("ip", ""), form.get("kind", "reservation"), form.get("mac", ""),
                                       form.get("name", ""))
    a = res["address"]
    msg = (f"Reserved {a['ip']} for {a['mac']}." if a["kind"] == "reservation" else f"Recorded {a['ip']} (static).")
    return res, msg + "".join(f" Warning: {w}." for w in res.get("warnings") or [])


def _back(site, subnet=""):
    """Purpose: the Networks tab on the site (and subnet) a form came from.
    Inputs:  site — the site shown; subnet — the subnet shown ("" none).
    Returns: str, "/networks?site=…[&subnet=…]&" ready for the outcome's query.
    Fails:   never.
    Feeds:   _request, _local."""
    q = {"site": site, **({"subnet": subnet} if subnet else {})}
    return "/networks?" + urllib.parse.urlencode(q) + "&"


def _request(h, form):
    """Purpose: ask a site below to scan one of its subnets through the agent (manual 1.10.4.29.3), and go back to the
             Networks tab on that site and subnet, saying the request was written and where its answer shows.
    Inputs:  h — the request handler (redirect); form — dict (site, subnet: the subnet's name, cidr).
    Returns: 303 with msg or err.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   networks_scan_post."""
    site, name = form.get("site", ""), form.get("subnet", "")
    back = _back(site, name)
    try:
        r = actions.request_scan(site, form.get("cidr", "") or name)
    except actions.ValidationError as exc:
        return h.redirect(back + urllib.parse.urlencode({"err": str(exc)}))
    return h.redirect(back + urllib.parse.urlencode({"msg": (
        f"Scan of {r['cidr']} requested at {r['site']} ({r['id']}). {r['site']}'s plan poll runs it within about 30 s: "
        f"reload this page to see its answer in Scans at {r['site']}.")}))


def _local(h, form):
    """Purpose: set whether a site below may scan locally through the agent (manual 1.10.4.29.4), and go back to the
             Networks tab on that site saying what it is now.
    Inputs:  h — the request handler (redirect); form — dict (site, allowed: on or off).
    Returns: 303 with msg or err.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   networks_scan_post."""
    site = form.get("site", "")
    try:
        r = actions.set_local_scan(site, form.get("allowed", ""))["result"]
    except actions.ValidationError as exc:
        return h.redirect(_back(site) + urllib.parse.urlencode({"err": str(exc)}))
    return h.redirect(_back(site) + urllib.parse.urlencode({"msg": (
        f"Local scans at {r['site']}: {'allowed' if r['allowed'] else 'off'} (set by {r['set_by']}). The next scan "
        "there reads it.")}))


def networks_scan_post(h, sess, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /networks/scan (manual 1.10.4.22): [] scans the chosen
             subnet and shows what answered; ["record"] records one address the scan found and goes back to the scan
             page with the outcome; ["request"] asks a site below to scan one of its subnets; ["local"] sets whether a
             site below may scan locally (decision 2.1.10.30).
    Inputs:  h — the request handler (send, redirect, deny); sess — the session; parts — segments after
             /networks/scan; form — dict (subnet; or ip, kind, mac, name; or site, subnet, cidr; or site, allowed).
    Returns: 200 the scan's result page; 303 back to /networks/scan with err when the agent refused the scan; the
             record's 303 (saved_and_applied); ["request"] and ["local"]: 303 back to the Networks tab on that site
             with what was done or why it was refused; 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    if parts in ([], [""]):
        try:
            result = actions.scan_subnet(form.get("subnet", ""))
        except actions.ValidationError as exc:
            return h.redirect("/networks/scan?" + urllib.parse.urlencode({"err": str(exc)}))
        scan = actions.scannable_subnets()
        return h.send(200, views.ipam_scan(page_context(sess), scan["subnets"], result, local=scan.get("local"),
                                           local_error=scan.get("local_error", "")))
    if parts == ["record"]:
        return saved_and_applied(h, "/networks/scan", lambda: _record(form))
    if parts == ["request"]:
        return _request(h, form)
    if parts == ["local"]:
        return _local(h, form)
    return h.deny(404, "Not found.")
