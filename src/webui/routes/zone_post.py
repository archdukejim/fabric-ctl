import urllib.parse

from webui import agentclient as actions
from webui.routes.held import held, q
from webui.routes.picked_record import picked_record

RECORD_FIELDS = ("name", "value", "ip", "target", "text", "priority", "weight", "port")


def _ticked(form, prefix):
    """Purpose: the networks a row ticked (2.1.4.18): its <prefix>_<n> boxes, each a network, and <prefix>_all for
             every network (a box left unticked is not sent at all).
    Inputs:  form — dict from read_form; prefix — "nw" (the zone's Networks row) or "sp" (a split's networks).
    Returns: the ticked values joined by commas, "all" first when ticked (so every network beside a network reaches
             the agent, which refuses it); "" when none is ticked (refused there too).
    Fails:   never.
    Feeds:   zone_post."""
    picked = [v for k, v in sorted(form.items()) if k.startswith(prefix + "_") and k != prefix + "_all" and v]
    return ",".join((["all"] if form.get(prefix + "_all") else []) + picked)


def _tab(form, body):
    """Purpose: a record change's tab (2.1.4.18): the split's index when the row was in a split's tab.
    Inputs:  form — dict from read_form (split: digits, or absent for All networks); body — the change's body.
    Returns: body, with "split" when the form named one.
    Fails:   never.
    Feeds:   zone_post."""
    split = str(form.get("split") or "")
    return {**body, "split": int(split)} if split.isdigit() else body


def zone_post(h, user, path, form):
    """Purpose: DNS records and a zone's networks and splits: each change held for DNS' Apply (decision 2.1.8.18).
    Inputs:  h — the request handler (back, deny); user — the signed-in person (unused: the hold is the session's);
             path — /bind9/zone/<key>/add (form: type, name, value, and priority for MX, priority, weight and port for
             SRV; ip, target and text are still read), …/update (type, index, old_name, then the new fields as add's:
             a record changed in its row, 2.1.4.15) or …/delete (type, index, name, as the row's bin sends them; or
             record: "<type>|<index>|<name>"), each with split (a split's tab, 2.1.4.18; absent: All networks);
             …/networks (nw_all, nw_<n>: the zone's networks), …/splits (sp_<n>: a new split's networks),
             …/splits/update (split, old, sp_<n>) or …/splits/delete (split, old); form — dict.
    Returns: 303 back to /dns/zones?zone=<key> (and &split=<n> for a split's tab) saying it waits for Apply, or the
             refusal (an unsupported type, no record picked, the permission missing); the agent's own refusals
             (fabric's own names, a record or split changed since it was shown, a network not offered) come at Apply,
             on the Review.
    Fails:   404 for another operation; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/zone/…)."""
    rest = urllib.parse.unquote(path[len("/bind9/zone/"):])
    key, _, op = rest.rpartition("/")
    if key.endswith("/splits"):                 # …/splits/update, …/splits/delete
        key, op = key[:-len("/splits")], "splits/" + op
    back = "/dns/zones?zone=" + urllib.parse.quote(key, safe="")
    split = str(form.get("split") or "")
    tab_back = back + (f"&split={split}" if split.isdigit() else "")
    if op == "add":
        rtype = form.get("type", "")
        if rtype not in actions.RECORD_TYPES:
            return h.back(tab_back, err="unsupported record type")
        body = {"type": rtype, **{k: form.get(k, "") for k in RECORD_FIELDS}}
        return held(h, tab_back, f"zones/{q(key)}/records", _tab(form, body))
    if op == "update":                          # a record replaced in place (2.1.4.15)
        rtype, index = form.get("type", ""), form.get("index", "")
        if rtype not in actions.RECORD_TYPES or not index.isdigit():
            return h.back(tab_back, err="pick a record to change")
        body = {"type": rtype, "index": int(index), "old_name": form.get("old_name", ""),
                **{k: form.get(k, "") for k in RECORD_FIELDS}}
        return held(h, tab_back, f"zones/{q(key)}/records/update", _tab(form, body))
    if op == "delete":
        rtype, index, name = picked_record(form)
        if not rtype or not index.isdigit():
            return h.back(tab_back, err="pick a record to delete")
        return held(h, tab_back, f"zones/{q(key)}/records/delete",
                    _tab(form, {"type": rtype, "index": int(index), "name": name}))
    if op == "networks":                        # the zone's networks (2.1.4.18)
        return held(h, back, f"zones/{q(key)}/networks", {"networks": _ticked(form, "nw")})
    if op == "splits":                          # a new split, a copy of All networks (2.1.4.18)
        return held(h, back, f"zones/{q(key)}/splits", {"subnets": _ticked(form, "sp")})
    if op in ("splits/update", "splits/delete"):
        if not split.isdigit():
            return h.back(back, err="pick a split")
        body = {"split": int(split), "old": form.get("old", "")}
        if op == "splits/update":
            return held(h, tab_back, f"zones/{q(key)}/splits/update", {**body, "subnets": _ticked(form, "sp")})
        return held(h, back, f"zones/{q(key)}/splits/delete", body)
    return h.deny(404, "Not found.")
