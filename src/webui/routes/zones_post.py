import urllib.parse

from webui import agentclient as actions


def zones_post(h, user, parts, form):
    """Purpose: DNS zones: add one, or remove one with its records (served or dropped in seconds: no Apply).
    Inputs:  h — the request handler (redirect, deny); user — the signed-in person; parts — URL-decoded segments after
             /bind9/zones/: ['new'] (form name, hide_public) or [<key>, 'remove'] (form confirm: the name typed
             again); form — dict.
    Returns: 303 to the new zone's page with msg, or to /bind9 with msg after a removal; on a ValidationError 303
             back (the zone the form was on) with err, the agent's reason.
    Fails:   404 for another path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zones/…)."""
    try:
        if parts == ["new"]:
            res = actions.add_zone(user, form.get("name", ""), bool(form.get("hide_public")))
            msg = f"Zone {res['name']} added: BIND answers for it now. Add its records below."
            return h.redirect("/bind9?" + urllib.parse.urlencode({"zone": res["key"], "msg": msg}))
        if len(parts) == 2 and parts[1] == "remove":
            res = actions.remove_zone(user, parts[0], form.get("confirm", ""))
            msg = f"Zone {res['name']} removed with its {res['records']} record(s)."
            return h.redirect("/bind9?" + urllib.parse.urlencode({"msg": msg}))
    except actions.ValidationError as exc:
        back = {"zone": parts[0]} if len(parts) == 2 else {}
        return h.redirect("/bind9?" + urllib.parse.urlencode({**back, "err": str(exc)}))
    return h.deny(404, "Not found.")
