from webui import agentclient as actions
from webui.views.constants import DNS_FILTER_SECTIONS

# what a post changes -> the section it goes back to
BACK = {"lists": "lists", "lists/set": "lists", "lists/delete": "lists", "fetch": "lists", "rules": "rules",
        "rules/delete": "rules", "upstreams": "settings", "groups": "groups", "groups/delete": "groups",
        "safe-search": "settings"}
FIELDS = ("name", "url", "enabled", "kind", "upstreams", "group", "clients", "on", "youtube")


def _message(what, res):
    """Purpose: the line shown after a change.
    Inputs:  what — the change (a BACK key); res — the agent's answer.
    Returns: str.
    Fails:   never.
    Feeds:   dns_filter_post."""
    r = res.get("result") or {}
    whose = f" for {r['group']}" if isinstance(r, dict) and r.get("group") else ""
    if what in ("lists", "lists/set"):
        state = "ticked" if r.get("enabled") else "unticked"
        if r.get("added"):
            state = "added and ticked"
        fetching = "; its first copy is being fetched, then it is used." if res.get("fetching") else "."
        return f"{r.get('name')} {state}{fetching}"
    if what == "lists/delete":
        return f"{r.get('name')} removed."
    if what == "fetch":
        return "Fetching every list and AdGuard's catalogue now; reload this page in a minute."
    if what == "rules":
        verb = "allowed" if r.get("kind") == "allow" else "blocked"
        return f"{r.get('name')} {verb}{whose}, with every name below it" + (" (it left the other rule)."
                                                                             if r.get("moved") else ".")
    if what == "rules/delete":
        return f"{r.get('name')} is no longer {'allowed' if r.get('kind') == 'allow' else 'blocked'} by a rule{whose}."
    if what == "groups":
        return (f"Group {r.get('name')} added" if r.get("added") else f"Group {r.get('name')} changed") + \
            f": {' '.join(r.get('clients') or [])}."
    if what == "groups/delete":
        return f"Group {r.get('name')} removed: its clients are answered as everyone."
    if what == "safe-search":
        return f"Strict safe search {'on, YouTube ' + str(r.get('youtube')) if r.get('on') else 'off'}" + \
            (whose or " for everyone") + "."
    ups = res.get("result") if isinstance(res.get("result"), list) else []
    return "Upstreams saved: " + ", ".join(f"{u['address']} ({u['name']})" for u in ups) + "."


def dns_filter_post(h, parts, form):
    """Purpose: One DNS filter tab change (manual 1.12.2.14, 1.12.2.15, 1.12.3.8), saved and made in seconds by
             fabric-agent, then back to its section with the outcome; a Block or Allow pressed in the query log goes
             back there, a group's change to Groups.
    Inputs:  h — the request handler (back, deny); parts — segments after /dns-filter/: ["lists"], ["lists",
             "set"], ["lists", "delete"], ["rules"], ["rules", "delete"], ["upstreams"], ["groups"], ["groups",
             "delete"], ["safe-search"], ["fetch"]; form — dict (name, url, enabled, kind, upstreams, group, clients,
             on, youtube; back: a section to return to). An unchecked safe-search box sends no "on": off.
    Returns: 303 to /dns-filter?view=<section> with what was done as its message, or why not when the agent refused
             the change (nothing saved) or it waits (saved; why: AdGuard not answering); 404 for another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/dns-filter/…)."""
    what = "/".join(parts)
    if what not in BACK:
        return h.deny(404, "Not found.")
    back = form.get("back") if form.get("back") in [s for s, _ in DNS_FILTER_SECTIONS] else BACK[what]
    body = {k: form.get(k, "") for k in FIELDS}
    where = "/dns-filter" + ("" if back == "overview" else "?view=" + back)
    try:
        res = actions.dns_filter_change(what, {} if what == "fetch" else body)
    except actions.ValidationError as e:
        return h.back(where, err=str(e))
    msg = _message(what, res)
    if what != "fetch" and not res.get("applied"):
        return h.back(where, err=msg + " Saved, but not in use yet: " + str(res.get("waiting") or "")[-300:])
    return h.back(where, msg=msg)
