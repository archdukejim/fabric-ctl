import urllib.parse

from webui import agentclient as actions


def zone_post(h, user, path, form):
    """Purpose: DNS records: add one to a zone, or delete one (published by the next Apply).
    Inputs:  h — the request handler (redirect, deny); user — the signed-in person; path — /bind9/zone/<key>/add (form:
             type, name, value, and priority for MX, priority, weight and port for SRV; ip, target and text are still
             read) or …/delete (type, index, name); form — dict.
    Returns: 303 back to /bind9?zone=<key> with msg, or err on a ValidationError (fabric's own names among them:
             their delete is refused, naming the setting they follow, 2.1.2.22).
    Fails:   404 for another operation; a non-numeric index raises ValueError (500); AgentError, PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zone/…)."""
    rest = urllib.parse.unquote(path[len("/bind9/zone/"):])
    key, _, op = rest.rpartition("/")
    back = "/bind9?zone=" + urllib.parse.quote(key)
    try:
        if op == "add":
            rtype = form.get("type", "")
            if rtype not in actions.RECORD_TYPES:
                raise actions.ValidationError("unsupported record type")
            rec = actions.add_record(user, key, rtype, form)
            msg = f"Added {rtype} {rec['name']}. Apply to publish."
        elif op == "delete":
            actions.delete_record(user, key, form.get("type", ""), int(form.get("index", -1)), form.get("name", ""))
            msg = "Record deleted. Apply to publish."
        else:
            return h.deny(404, "Not found.")
        return h.redirect(back + "&" + urllib.parse.urlencode({"msg": msg}))
    except actions.ValidationError as exc:
        return h.redirect(back + "&" + urllib.parse.urlencode({"err": str(exc)}))
