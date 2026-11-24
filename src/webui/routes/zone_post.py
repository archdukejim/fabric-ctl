import urllib.parse

from webui import agentclient as actions
from webui.routes.held import held, q
from webui.routes.picked_record import picked_record

RECORD_FIELDS = ("name", "value", "ip", "target", "text", "priority", "weight", "port")


def _subnets(form):
    """Purpose: the subnets a record's row ticked (2.1.4.17): its sn_<n> boxes, each a subnet, or sn_all; sn_shown
             says the row had the boxes (a box left unticked is not sent at all).
    Inputs:  form — dict from read_form.
    Returns: the ticked boxes' values joined by commas ("all" first when ticked, so every subnet beside a subnet
             reaches the agent, which refuses it), "" when the boxes were shown and none was ticked (refused too), or
             None when the row had no boxes (a reverse zone; the agent's default applies).
    Fails:   never.
    Feeds:   zone_post."""
    if not form.get("sn_shown"):
        return None
    picked = [v for k, v in sorted(form.items()) if k.startswith("sn_") and k not in ("sn_all", "sn_shown") and v]
    return ",".join((["all"] if form.get("sn_all") else []) + picked)


def zone_post(h, user, path, form):
    """Purpose: DNS records: add one to a zone, or delete one, each held for DNS' Apply (decision 2.1.8.18).
    Inputs:  h — the request handler (back, deny); user — the signed-in person (unused: the hold is the session's);
             path — /bind9/zone/<key>/add (form: type, name, value, and priority for MX, priority, weight and port for
             SRV; ip, target and text are still read; the subnets it answers as sn_<n> boxes or sn_all, 2.1.4.17),
             …/update (type, index, old_name, then the new fields as add's: a record changed in its row, 2.1.4.15)
             or …/delete (type, index, name, as the row's bin sends them; or record: "<type>|<index>|<name>");
             form — dict.
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
        body = {"type": rtype, **{k: form.get(k, "") for k in RECORD_FIELDS}}
        if _subnets(form) is not None:
            body["subnets"] = _subnets(form)
        return held(h, back, f"zones/{q(key)}/records", body)
    if op == "update":                          # a record replaced in place (2.1.4.15)
        rtype, index = form.get("type", ""), form.get("index", "")
        if rtype not in actions.RECORD_TYPES or not index.isdigit():
            return h.back(back, err="pick a record to change")
        body = {"type": rtype, "index": int(index), "old_name": form.get("old_name", ""),
                **{k: form.get(k, "") for k in RECORD_FIELDS}}
        if _subnets(form) is not None:
            body["subnets"] = _subnets(form)
        return held(h, back, f"zones/{q(key)}/records/update", body)
    if op == "delete":
        rtype, index, name = picked_record(form)
        if not rtype or not index.isdigit():
            return h.back(back, err="pick a record to delete")
        return held(h, back, f"zones/{q(key)}/records/delete", {"type": rtype, "index": int(index), "name": name})
    return h.deny(404, "Not found.")
