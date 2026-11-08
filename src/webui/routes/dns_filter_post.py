from webui import agentclient as actions
from webui.routes.dns_filter_page import dns_filter_page
from webui.routes.held import held
from webui.session.page_context import page_context
from webui.views.constants import DNS_FILTER_SECTIONS

# what a post changes -> the section it goes back to (each change waits for the tab's Apply, 1.12.3.17)
BACK = {"lists": "lists", "lists/delete": "lists", "lists/apply": "lists", "fetch": "lists",
        "rules": "rules", "rules/delete": "rules", "upstreams": "settings", "groups": "groups",
        "groups/delete": "groups", "safe-search": "settings"}
FIELDS = ("name", "url", "enabled", "kind", "upstreams", "group", "clients", "on", "youtube")


def _anchor(what, form, back):
    """Purpose: where on its section the page comes back to after a post (1.12.3.17: not the top): the card of the
             group a change is for, the settings card changed, the lists' form.
    Inputs:  what — the change (a BACK key); form — the posted form; back — the section.
    Returns: an element id of the page ("" for none).
    Fails:   never.
    Feeds:   dns_filter_post."""
    group = str(form.get("group") or "").strip().lower()
    if what in ("groups", "groups/delete"):
        name = str(form.get("name") or "").strip().lower()
        return f"group-{name}" if what == "groups" and name else "add-group"
    if back == "groups" and group:
        return f"group-{group}"
    if back == "settings":
        return "upstreams" if what == "upstreams" else "safe-search"
    return back


def _lists_apply(h, sess, form, where):
    """Purpose: the lists form's Apply (manual 1.12.3.17): every box at once is held as one change (fabric-agent keeps
             those that differ from the site's lists), then the tab's changes are applied together as one job.
    Inputs:  h — the request handler; sess — the session (a refused Apply's page); form — on-<list id> for each box
             ticked, shown (the ids the page showed), version (the page's lists_version); where — the lists section.
    Returns: 303 to the lists with what is being applied, or that nothing waits; a refusal of the ticks (the memory
             rule, a malformed form) is the lists page again with why, the boxes as they were sent; a page whose
             lists changed since is refused the same way, the lists shown as they are now (dns_filter_page).
    Fails:   AgentError, PermissionDenied and AuthError propagate.
    Feeds:   dns_filter_post."""
    shown = str(form.get("shown") or "").split()
    body = {"on": [i for i in shown if form.get(f"on-{i}") == "on"], "shown": shown,
            "version": str(form.get("version") or "")}
    try:
        held_now = actions.hold_change("dns-filter/lists/ticks", body)
    except actions.ValidationError as exc:
        return dns_filter_page(h, page_context(sess), {"view": "lists"}, sent=body, err=str(exc))
    if not held_now.get("pending"):
        return h.back(where, msg="Nothing to apply: no box was changed and no other change waits.")
    try:
        actions.pending_action("dns-filter", "apply")
    except actions.ValidationError as exc:      # an apply of this page of theirs still running
        return h.back(where, err=f"{exc}; the ticks wait for Apply ({held_now['pending']} pending).")
    n = held_now["pending"]
    return h.back(where, msg=f"Applying {n} change{'' if n == 1 else 's'}: the page shows them once done "
                             "(Review shows each one's progress).")


def dns_filter_post(h, sess, parts, form):
    """Purpose: One DNS filter tab change (manual 1.12.2.14, 1.12.2.15, 1.12.3.17): held by fabric-agent for the tab's
             Apply (the bar at the top, or the lists form's Apply changes, which applies them all with the ticks),
             then back to its section, where it was on it; "Fetch every list now" is done at once.
    Inputs:  h — the request handler (back, deny, send); sess — the session; parts — segments after /dns-filter/:
             ["lists"], ["lists", "delete"], ["lists", "apply"], ["rules"], ["rules", "delete"],
             ["upstreams"], ["groups"], ["groups", "delete"], ["safe-search"], ["fetch"]; form — dict (name, url,
             enabled, kind, upstreams, group, clients, on, youtube; back: a section to return to; the lists form's
             on-<id>, shown and version). An unchecked safe-search box sends no "on": off.
    Returns: 303 to /dns-filter?view=<section>#<where> with "Waiting for Apply: ..." (or what was started), or why
             not when fabric-agent refused it (nothing held); the lists form's Apply as _lists_apply; 404 for
             another path.
    Fails:   AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/dns-filter/…)."""
    what = "/".join(parts)
    if what not in BACK:
        return h.deny(404, "Not found.")
    back = form.get("back") if form.get("back") in [s for s, _ in DNS_FILTER_SECTIONS] else BACK[what]
    anchor = _anchor(what, form, back)
    where = "/dns-filter" + ("" if back == "overview" else "?view=" + back) + (f"#{anchor}" if anchor else "")
    if what == "lists/apply":
        return _lists_apply(h, sess, form, where)
    if what == "fetch":
        try:
            actions.dns_filter_change("fetch", {})
        except actions.ValidationError as e:
            return h.back(where, err=str(e))
        return h.back(where, msg="Fetching every list and AdGuard's catalogue now; reload this page in a minute.")
    body = {k: form.get(k, "") for k in FIELDS if form.get(k, "") != ""}
    return held(h, where, f"dns-filter/{what}", body)
