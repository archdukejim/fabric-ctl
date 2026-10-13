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


def _policy(h, org, form):
    """Purpose: set one level of the scan policy through the agent and go back where the form came from: the scan page
             (back=scan) or the Networks tab on the site it showed (manual 1.10.4.27.5).
    Inputs:  h — the request handler (redirect); org — bool: the organisation's level; form — dict (site, policy,
             enforced, back).
    Returns: 303 with msg (what the policy is now) or err (why the agent refused).
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   networks_scan_post."""
    site = form.get("site", "")
    back = "/networks/scan?" if form.get("back") == "scan" else "/networks?" + (
        urllib.parse.urlencode({"site": site}) + "&" if site else "")
    try:
        res = actions.set_scan_policy("org" if org else "site", site, form.get("policy", ""),
                                      form.get("enforced", "") if org else "")
    except actions.ValidationError as exc:
        return h.redirect(back + urllib.parse.urlencode({"err": str(exc)}))
    r = res["result"]
    msg = (("The organisation's scan policy" if org else f"{r['site']}'s scan policy") + f" is {r['policy']}"
           + ((", enforced" if r.get("enforced") else ", not enforced") if org and r.get("enforced") is not None
              else "") + ". The next scan reads it.")
    return h.redirect(back + urllib.parse.urlencode({"msg": msg}))


def networks_scan_post(h, sess, parts, form):
    """Purpose: route a signed-in, CSRF-checked POST under /networks/scan (manual 1.10.4.22): [] scans the chosen
             subnet and shows what answered; ["record"] records one address the scan found and goes back to the scan
             page with the outcome.
    Inputs:  h — the request handler (send, redirect, deny); sess — the session; parts — segments after
             /networks/scan; form — dict (subnet; or ip, kind, mac, name; or site, policy, enforced, back).
    Returns: 200 the scan's result page; 303 back to /networks/scan with err when the agent refused the scan; the
             record's 303 (saved_and_applied); ["policy"] and ["policy", "org"]: a site's or the organisation's scan
             policy set (decision 2.1.10.28), 303 back with what it is now or why it was refused; 404 for another
             path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action."""
    if parts in ([], [""]):
        try:
            result = actions.scan_subnet(form.get("subnet", ""))
        except actions.ValidationError as exc:
            return h.redirect("/networks/scan?" + urllib.parse.urlencode({"err": str(exc)}))
        scan = actions.scannable_subnets()
        return h.send(200, views.ipam_scan(page_context(sess), scan["subnets"], result, policy=scan.get("policy"),
                                           policy_error=scan.get("policy_error", "")))
    if parts == ["record"]:
        return saved_and_applied(h, "/networks/scan", lambda: _record(form))
    if parts in (["policy"], ["policy", "org"]):
        return _policy(h, parts == ["policy", "org"], form)
    return h.deny(404, "Not found.")
