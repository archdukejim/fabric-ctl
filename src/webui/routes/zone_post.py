import urllib.parse

from webui import agentclient as actions
from webui.routes.held import held, q
from webui.routes.picked_record import picked_record

RECORD_FIELDS = ("name", "value", "ip", "target", "text", "priority", "weight", "port")


def zone_post(h, user, path, form):
    """Purpose: DNS records: add one to a zone, or delete one, each held for DNS' Apply (decision 2.1.8.18).
    Inputs:  h — the request handler (back, deny); user — the signed-in person (unused: the hold is the session's);
             path — /bind9/zone/<key>/add (form: type, name, value, and priority for MX, priority, weight and port for
             SRV; ip, target and text are still read) or …/delete (record: "<type>|<index>|<name>", as the page's
             select sends it; or type, index, name); form — dict.
    Returns: 303 back to /dns/zones?zone=<key> saying it waits for Apply, or the refusal (an unsupported type, no
             record picked, the permission missing); the agent's own refusals (fabric's own names, a record changed
             since it was shown) come at Apply, on the Review.
    Fails:   404 for another operation; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zone/…)."""
    rest = urllib.parse.unquote(path[len("/bind9/zone/"):])
    key, _, op = rest.rpartition("/")
    back = "/dns/zones?zone=" + urllib.parse.quote(key, safe="")
    if op == "add":
        rtype = form.get("type", "")
        if rtype not in actions.RECORD_TYPES:
            return h.back(back, err="unsupported record type")
        return held(h, back, f"zones/{q(key)}/records", {"type": rtype, **{k: form.get(k, "") for k in RECORD_FIELDS}})
    if op == "delete":
        rtype, index, name = picked_record(form)
        if not rtype or not index.isdigit():
            return h.back(back, err="pick a record to delete")
        return held(h, back, f"zones/{q(key)}/records/delete", {"type": rtype, "index": int(index), "name": name})
    return h.deny(404, "Not found.")
