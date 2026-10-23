import urllib.parse

from webui import agentclient as actions


def zones_post(h, user, parts, form):
    """Purpose: DNS zones: add one, or remove one with its records (served or dropped in seconds: no Apply).
    Inputs:  h — the request handler (back, deny); user — the signed-in person; parts — URL-decoded segments after
             /bind9/zones/: ['new'] (form name, hide_public) or [<key>, 'remove'] (form confirm: the name typed
             again); form — dict.
    Returns: 303 to the new zone's page, or to /dns/zones after a removal, with what was done; on a refusal 303
             back (the zone the form was on) with the agent's reason (messages: Handler.back).
    Fails:   404 for another path; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zones/…)."""
    try:
        if parts == ["new"]:
            res = actions.add_zone(user, form.get("name", ""), bool(form.get("hide_public")))
            msg = f"Zone {res['name']} added: BIND answers for it now. Add its records below."
            return h.back("/dns/zones?zone=" + urllib.parse.quote(res["key"], safe=""), msg=msg)
        if len(parts) == 2 and parts[1] == "remove":
            res = actions.remove_zone(user, parts[0], form.get("confirm", ""))
            msg = f"Zone {res['name']} removed with its {res['records']} record(s)."
            return h.back("/dns/zones", msg=msg)
    except actions.ValidationError as exc:
        back = "/dns/zones" + ("?zone=" + urllib.parse.quote(parts[0], safe="") if len(parts) == 2 else "")
        return h.back(back, err=str(exc))
    return h.deny(404, "Not found.")
