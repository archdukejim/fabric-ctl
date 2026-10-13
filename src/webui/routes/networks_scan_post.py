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


def networks_scan_post(h, sess, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /networks/scan (manual 1.10.4.21): [] scans the chosen
             subnet and shows what answered; ["record"] records one address the scan found and goes back to the scan
             page with the outcome.
    Inputs:  h — the request handler (send, redirect, deny); sess — the session; parts — segments after
             /networks/scan; form — dict (subnet; or ip, kind, mac, name).
    Returns: 200 the scan's result page; 303 back to /networks/scan with err when the agent refused the scan; the
             record's 303 (saved_and_applied); 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    if parts in ([], [""]):
        try:
            result = actions.scan_subnet(form.get("subnet", ""))
        except actions.ValidationError as exc:
            return h.redirect("/networks/scan?" + urllib.parse.urlencode({"err": str(exc)}))
        return h.send(200, views.ipam_scan(page_context(sess), actions.scannable_subnets()["subnets"], result))
    if parts == ["record"]:
        return saved_and_applied(h, "/networks/scan", lambda: _record(form))
    return h.deny(404, "Not found.")
