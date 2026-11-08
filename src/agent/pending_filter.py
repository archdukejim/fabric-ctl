# The DNS filter tab's changes held for its Apply (manual 1.12.3.17, decision 2.1.12.14): every settings change of
# the tab; the query log's search and "Fetch every list now" are not changes and are done at once
from fabriclib.common.errors import ValidationError

PAGE = "dns-filter"
HELD = ("lists", "lists/set", "lists/ticks", "lists/delete", "rules", "rules/delete", "upstreams", "groups",
        "groups/delete", "safe-search")


def filter_page_of(route):
    """Purpose: whether a change is the DNS filter tab's, held for its Apply.
    Inputs:  route — the change's segments after /v1/.
    Returns: "dns-filter", or None (not one of the tab's held changes).
    Fails:   never.
    Feeds:   agent/pending_thing.pending_page_of, post_pending, the dev preview."""
    return PAGE if route[:1] == ["dns-filter"] and "/".join(route[1:]) in HELD else None


def _group(body):
    """Purpose: the client group a change names, as fabriclib keys it ("" for everyone).
    Inputs:  body — the change's body.
    Returns: str.
    Fails:   never.
    Feeds:   describe_filter, filter_state, filter_key."""
    return str(body.get("group") or "").strip().lower()


def _names(items):
    """Purpose: the lists of a ticks change, as people read them.
    Inputs:  items — [{url, name}].
    Returns: str ("A, B"; "" for none).
    Fails:   never.
    Feeds:   describe_filter."""
    return ", ".join(str(i.get("name") or i.get("url") or "") for i in items if isinstance(i, dict))


def describe_filter(route, body):
    """Purpose: a DNS filter change in a sentence ("Block ads.example for kids", "Tick AdGuard DNS filter").
    Inputs:  route — segments after /v1/; body — its body.
    Returns: str.
    Fails:   never.
    Feeds:   agent/pending_thing.describe_change."""
    what, b = "/".join(route[1:]), body
    whose = f" for {_group(b)}" if _group(b) else ""
    if what == "lists/ticks":
        parts = [f"Tick {_names(b.get('tick') or [])}" if b.get("tick") else "",
                 f"untick {_names(b.get('untick') or [])}" if b.get("untick") else ""]
        return "; ".join(p for p in parts if p) or "Change no list"
    if what == "lists":
        return f"Add the list {b.get('name') or b.get('url', '')}"
    if what == "lists/set":
        return f"{'Tick' if str(b.get('enabled')) == 'on' else 'Untick'} {b.get('name') or b.get('url', '')}"
    if what == "lists/delete":
        return f"Remove the list {b.get('url', '')}"
    if what in ("rules", "rules/delete"):
        verb = "Allow" if b.get("kind") == "allow" else "Block"
        return (f"{verb} {b.get('name', '')}{whose}" if what == "rules"
                else f"Stop {'allowing' if verb == 'Allow' else 'blocking'} {b.get('name', '')}{whose}")
    if what == "upstreams":
        return "Set the upstreams to " + ", ".join(str(b.get("upstreams") or "").split())
    if what == "groups":
        return f"Set client group {b.get('name', '')}: {b.get('clients', '')}"
    if what == "groups/delete":
        return f"Remove client group {b.get('name', '')}"
    return f"Strict safe search {'on' if str(b.get('on')) in ('on', 'true', '1', 'yes') else 'off'}" + (
        whose or " for everyone")


def filter_key(route, body):
    """Purpose: which part of the DNS filter a held change changes: the lists, everyone's rules and safe search, one
             client group, the upstreams. Two changes of one Apply on the same part share it.
    Inputs:  route — segments after /v1/; body — its body.
    Returns: a tuple.
    Fails:   never.
    Feeds:   agent/pending_thing.thing_key."""
    what = "/".join(route[1:])
    if what.startswith("lists"):
        return PAGE, "lists"
    if what == "upstreams":
        return PAGE, "upstreams"
    if what.startswith("groups"):
        return PAGE, "group", str(body.get("name") or "").strip().lower()
    return (PAGE, "group", _group(body)) if _group(body) else (PAGE, "everyone")


def filter_state(route, body, v):
    """Purpose: the part of the DNS filter a held change changes, as vars.yaml has it now (decision 2.1.8.14): what
             its version is taken from at hold and checked against at Apply.
    Inputs:  route — segments after /v1/; body — its body; v — vars.
    Returns: the lists ({"lists": [...]}), the upstreams, everyone's rules and safe search, or the group (None for a
             group not there yet).
    Fails:   never.
    Feeds:   agent/pending_thing.thing_state."""
    key = filter_key(route, body)
    if key[1] == "lists":
        return {"lists": v.get("dns_filter_lists") or []}
    if key[1] == "upstreams":
        return {"upstreams": v.get("dns_filter_upstreams") or []}
    if key[1] == "everyone":
        return {k: v.get(f"dns_filter_{k}") for k in ("allow", "block", "safe_search", "youtube")}
    return next((g for g in v.get("dns_filter_groups") or [] if isinstance(g, dict)
                 and str(g.get("name") or "").lower() == key[2]), None)


def filter_check(owner, route, body):
    """Purpose: a held change of the tab checked as fabriclib checks it, nothing saved (change_dns_filter's dry run):
             when it is held, so a bad one is refused at once with why and nothing waits, and again at Apply,
             after the changes before it (the lists' memory rule over the whole set, 1.12.3.9).
    Inputs:  owner — the signed-in person; route — segments after /v1/; body — its body.
    Returns: None (not the tab's change, or it passes).
    Fails:   ValidationError with fabriclib's refusal.
    Feeds:   agent/post_pending (the store's check)."""
    if filter_page_of(route) is None:
        return None
    from agent.change_dns_filter import change_dns_filter
    change_dns_filter(route, owner, body, dry=True)
    return None


def filter_ticks(body, rows):
    """Purpose: the lists form's Apply as the change it holds (manual 1.12.3.17): the boxes ticked and the lists the
             page showed become the lists to tick and untick, those that differ from the site's now; a page whose
             lists changed since it was shown is refused, saying why, so it never undoes another change.
    Inputs:  body — the form's: {"on": [list ids ticked], "shown": [list ids the page showed], "version": the
             lists_version the page was shown with}; rows — filter_lists' rows now (or the preview's sample).
    Returns: {"tick": [{url, name}], "untick": [{url, name}]} (both empty when nothing differs).
    Fails:   ValidationError: a malformed body (on and shown lists of ids, version text), an id ticked that the page
             did not show, an id of no list, or the stale page ("the lists changed since this page was shown: ...").
    Feeds:   agent/post_pending (hold), the dev preview."""
    from fabriclib.dns_filter.common.lists_version import lists_version
    on, shown, version = body.get("on"), body.get("shown"), body.get("version")
    if not isinstance(on, list) or not isinstance(shown, list) or not isinstance(version, str) \
            or not all(isinstance(i, str) for i in on + shown):
        raise ValidationError("the lists' Apply: on and shown, lists of list ids, and the page's version")
    if set(on) - set(shown):
        raise ValidationError("a list ticked that the page did not show")
    by_id = {r["id"]: r for r in rows}
    unknown = [i for i in shown if i not in by_id]
    if version != lists_version(rows) or unknown:
        raise ValidationError("the lists changed since this page was shown (another person, or the host, ticked, "
                              "added or removed one): nothing was changed. They are shown again as they are now; "
                              "tick again and press Apply changes")
    tick = [{"url": by_id[i]["url"], "name": by_id[i]["name"]} for i in shown
            if i in on and not by_id[i].get("enabled")]
    untick = [{"url": by_id[i]["url"], "name": by_id[i]["name"]} for i in shown
              if i not in on and by_id[i].get("enabled")]
    return {"tick": tick, "untick": untick}


def filter_finish(routes):
    """Purpose: what the tab's changes need once all are done (manual 1.12.3.17): the filter applied once (the
             resolver reloaded, AdGuard Home through its API: nothing restarts), and one start of the lists job for
             a list ticked with no copy yet.
    Inputs:  routes — the routes being applied.
    Returns: (what, fn(actor)); fn returns its row's note: "" or a warning saying what waits and why (AdGuard not
             answering, the lists job not starting), or that the first copies are being fetched.
    Fails:   never (fn raises ValidationError when the settings do not render).
    Feeds:   agent/post_pending (_finish)."""
    lists = any(list(r)[:2] == ["dns-filter", "lists"] and list(r)[2:] != ["delete"] for r in routes)

    def apply_once(actor):
        from agent.apply_filter_now import apply_filter_now
        done = apply_filter_now(actor, "all" if lists else None)
        if done["waiting"]:
            return f"warning: saved, but not in use yet: {done['waiting']}"
        return "the first copy of a list ticked is being fetched, then it is used" if done["fetching"] else ""

    return "Apply the DNS filter (the resolver reloaded, AdGuard Home through its API; nothing restarts)", apply_once
