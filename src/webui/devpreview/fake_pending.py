import urllib.parse

from webui.devpreview.fabric_rules import ValidationError, required_permission, site_plan
from webui.devpreview.fake_account import managed
from webui.devpreview.fake_directory import PERSON_KEYS, kerberos_policy
from webui.devpreview.fake_groups import find_group
from webui.devpreview.fake_ous import fake_ous
from webui.devpreview.fake_grants import fake_grants
from webui.devpreview.fake_ipam import HERE, network_read
from webui.devpreview.sample_data import SAMPLE_ACCESS, SAMPLE_DNS_FILTER, SAMPLE_DOMAIN, SAMPLE_GPO, SAMPLE_RADIUS

try:                                       # the agent's own store and its words, from a checkout (as fabric_rules)
    import agent.pending_networks as pending_networks
    from agent.pending_store import PendingStore
    from agent.pending_thing import PAGES, describe_change, own_state, pending_page_of
    from agent.landing_note import landing_note
    from agent.pending_filter import filter_finish, filter_page_of, filter_state, filter_ticks
    pending_networks._this_site = lambda: HERE         # the sample's own site, not this machine's vars.yaml
except ImportError:
    PendingStore = None


def _find(rows, key, value):
    """Purpose: The sample row whose key is a value.
    Inputs:  rows — list of dicts; key, value — str.
    Returns: the row or None.
    Fails:   never.
    Feeds:   _thing."""
    return next((r for r in rows or [] if str(r.get(key)) == str(value)), None)


def _filter_vars():
    """Purpose: The sample DNS filter as vars.yaml has it, for the agent's own read of a held change (filter_state).
    Inputs:  none (reads SAMPLE_DNS_FILTER).
    Returns: dict of the dns_filter_* settings.
    Fails:   never.
    Feeds:   _thing."""
    d = SAMPLE_DNS_FILTER
    return {"dns_filter_lists": [{"name": r["name"], "url": r["url"], "enabled": r["enabled"]}
                                 for r in d["lists"] if r.get("on_site")],
            "dns_filter_upstreams": d["upstreams"], "dns_filter_allow": d["allow"], "dns_filter_block": d["block"],
            "dns_filter_safe_search": d["safe_search"]["on"], "dns_filter_youtube": d["safe_search"]["youtube"],
            "dns_filter_groups": d["groups"]}


def _check(state, route, body):
    """Purpose: The preview's check of a held DNS filter change, at hold and at Apply, as the agent's dry run makes
             it for the lists: the memory rule over the whole set (1.12.3.9), AdGuard Home's limit the sample's, or
             150 MiB with the preview's `tight` toggle (so the refusal can be seen).
    Inputs:  state — DevState (toggles); route — segments after /v1/; body — dict.
    Returns: None.
    Fails:   ValidationError naming the lists and the gap, as set_filter_lists says it.
    Feeds:   _store."""
    if route != ["dns-filter", "lists", "ticks"]:
        return None
    gone = {i.get("url") for i in body.get("untick") or []}
    new = {i.get("url") for i in body.get("tick") or []}
    rows = [r for r in SAMPLE_DNS_FILTER["lists"] if (r["enabled"] and r["url"] not in gone) or r["url"] in new]
    total = sum(r["memory_mb"] or 0 for r in rows)
    limit = 150.0 if state.toggles.get("tight") else SAMPLE_DNS_FILTER["memory"]["limit_mb"]
    if total * 2.5 > limit:
        names = ", ".join(f"{r['name']} (~{r['memory_mb']:.0f} MiB)" for r in rows if r["url"] in new)
        raise ValidationError(f"the ticked lists do not fit: {names} would take the set to about {total:.0f} MiB, "
                              f"{total * 2.5:.0f} MiB while AdGuard Home compiles them, {total * 2.5 - limit:.0f} MiB "
                              f"past its limit of {limit:.0f} MiB. Nothing was changed")
    return None


def _thing(state, route, body):
    """Purpose: The preview's read of what a change changes, as the agent's thing_state reads it (2.1.8.14).
    Inputs:  state — DevState; route — segments after /v1/; body — dict.
    Returns: the sample row or value (None for a new one).
    Fails:   never.
    Feeds:   fake_pending (the store's state)."""
    if pending_networks.networks_page_of(route):     # the address manager: as networks_state reads the plan
        site, read = pending_networks.networks_site(route, body), network_read(state)
        if site == "domain":
            return {"domain_options": read["option_sets"].get("domain")}
        if site not in read["plans"]:
            raise ValidationError(f"no such site: {site}")
        return {"plan": {k: x for k, x in site_plan(read, site).items() if k != "read"}}
    if filter_page_of(route):                        # the DNS filter tab (1.12.3.17): as the agent reads it
        return filter_state(route, body, _filter_vars())
    head, name = route[0], (route[1] if len(route) > 1 else body.get("uid") or body.get("name", ""))
    if route[:2] == ["account", "groups"]:            # a member change from My account: its managed group
        group = _find(managed(state), "name", route[2] if len(route) > 2 else "")
        if group is None:
            raise ValidationError(f"no group {route[2] if len(route) > 2 else ''}")
        return group
    if head == "people":                              # the row with its details, as the agent's read
        row = _find(state.data["people"]["users"], "uid", name)
        return {**row, **dict.fromkeys(PERSON_KEYS, ""), **(row.get("person") or {})} if row else None
    if head == "machines":                            # as the agent: its machine groups are the groups' things
        row = _find(SAMPLE_DOMAIN["machines"], "name", name)
        return {k: x for k, x in row.items() if k != "groups"} if row else None
    if head == "groups":                              # a new one: None; else the group, which must be there
        group = find_group(state, name)
        if group is None and len(route) > 1:
            raise ValidationError(f"no group {name} in the domain")
        return group
    if head == "host-groups":
        return _find(SAMPLE_ACCESS["groups"], "short", name) or _find(SAMPLE_ACCESS["groups"], "name", name)
    if head == "sudo":
        return _find(SAMPLE_ACCESS["sudo"], "name", name)
    if route == ["domain", "password-policy"]:
        return SAMPLE_DOMAIN["policy"]
    if route == ["domain", "kerberos", "policy"]:
        return kerberos_policy(state)
    if head == "radius":                              # a RADIUS client or a group mapping
        rows, key = ((SAMPLE_RADIUS["people"], "group") if route[1] == "people" else (SAMPLE_RADIUS["clients"], "name"))
        return _find(rows, key, route[2] if len(route) > 2 else body.get("group", ""))
    if head in ("devices", "roles"):                  # its own fields, as the agent reads them
        rows = (state.overview() or {}).get(head)
        return own_state(head, _find(rows, "name", name if len(route) > 1 else body.get("name", "")))
    if route[:2] == ["domain", "grants"]:             # the grant as the list has it, None for a new one
        name = route[2] if len(route) > 2 else body.get("name", "")
        return _find(fake_grants(state, None, ["domain", "grants"], None)["grants"], "name", name)
    if head == "ous":                                 # the whole tree, as the agent reads it
        return fake_ous(state, None, ["ous"], None)
    if head == "gpo":
        return {"settings": SAMPLE_GPO.get("settings"), "controls": SAMPLE_GPO.get("controls")}
    if head == "zones":                               # the zone as the preview keeps it; None for one not there
        key = route[1] if len(route) > 1 else str(body.get("name") or "").strip().rstrip(".").lower()
        return state.data["zones"].get(key)
    if head == "tsig":
        return _find(state.data["tsig"], "name", route[1])
    raise ValidationError("this change is not held in the preview")


def _finish(state, page, routes):
    """Purpose: What a page's changes still need once done, as the agent's finish says it (nothing runs here).
    Inputs:  state — DevState; page — a page id; routes — the routes applied.
    Returns: (what, fn(actor)) for the password policy, DNS' records, links and key removals, and the address
             manager's pages; None otherwise. DNS' fn returns the agent's note on the landing page's certificate
             (2.1.8.29) when a record of the site's zone changed: the preview has no certificate, so it says it as a
             renamed alias would.
    Fails:   never.
    Feeds:   _store."""
    if page == "dns-filter":                           # applied once (1.12.3.17): nothing applied here
        return filter_finish(routes)[0], lambda actor: state.log("DNS_FILTER_APPLY", "dev preview: nothing applied")
    if page == "policies" and ["domain", "password-policy"] in routes:
        return "Write the policy into the domain (restarts only what changed)", lambda actor: None
    if page in ("networks", "options"):                # this site's plan applied once (1.10.4.40.3)
        return ("Apply this site's plan to Kea and the firewall (restarts only what changed)",
                lambda actor: state.log("IPAM_APPLY", "dev preview: nothing applied"))
    if page == "zones" and any(list(r) != ["zones"] and list(r)[2:] != ["delete"] or r[0] == "tsig" for r in routes):
        site = any(list(r)[:2] == ["zones", "dynamic_zone_var"] for r in routes)

        def publish(actor):
            state.log("APPLY_DNS", "dev preview: nothing reloaded")
            return landing_note({"missing": [], "extra": ["(dev preview) a name it held"]}) if site else ""

        return "Publish to BIND and the landing page (reloads only BIND)", publish
    return None


def _store(state, who, run):
    """Purpose: The preview's pending store: the agent's own PendingStore over the sample data, its jobs done at once.
    Inputs:  state — DevState (keeps the store); who — the preview's person; run — (route, body) -> answer: the fake
             agent's change.
    Returns: the PendingStore.
    Fails:   never.
    Feeds:   fake_pending."""
    if getattr(state, "pending", None) is None:
        def start_job(kind, owner, fn):
            jobs = state.data.setdefault("jobs", {})
            job_id = f"dev-{len(jobs) + 1}"
            jobs[job_id] = {"id": job_id, "kind": kind, "state": "done", "error": "", "result": fn()}
            return {"id": job_id}

        state.pending = PendingStore(run=lambda route, actor, body, perms, session: run(route, body),
                                     state=lambda route, body: _thing(state, route, body),
                                     need=lambda route: required_permission("POST", route), start_job=start_job,
                                     finish=lambda page, routes: _finish(state, page, routes),
                                     check=lambda owner, route, body: _check(state, route, body))
    return state.pending


def fake_pending(state, who, method, route, body, run):
    """Purpose: The fake agent's Apply per page (manual 1.8.6.5): GET /v1/pending and /v1/pending/<page>, POST
             /v1/pending/hold and /v1/pending/<page>/drop|discard|apply, with the agent's own store and checks.
    Inputs:  state — DevState; who — {"user", "perms"}; method — "GET" or "POST"; route — segments after /v1/; body —
             dict; run — (route, body) -> answer: the fake agent's change (raising ValidationError for a refusal).
    Returns: the answer, or None for another route (or without the agent's code: the preview then holds nothing).
    Fails:   ValidationError as the agent refuses.
    Feeds:   fake_agent."""
    if route[:1] != ["pending"] or PendingStore is None:
        return None
    store, user, perms = _store(state, who, run), who["user"], set(who["perms"])

    def may_see(page):
        return PAGES.get(page) == "session" or PAGES.get(page) in perms

    if method == "GET":
        if route == ["pending"]:
            return store.counts(user, may_see)
        return store.page(user, route[1], may_see) if len(route) == 2 and route[1] in PAGES else None
    if route == ["pending", "hold"]:
        parts = [urllib.parse.unquote(p) for p in str(body.get("route", "")).split("/") if p]
        page = pending_page_of(parts)
        if page is None:
            raise ValidationError("this change is not held: it is done at once")
        change = body.get("body") or {}
        if parts == ["dns-filter", "lists", "ticks"]:     # the lists form, as the agent takes it (1.12.3.17)
            change = filter_ticks(change, SAMPLE_DNS_FILTER["lists"])
            if not change["tick"] and not change["untick"]:
                return {"id": None, "page": page, "what": "",
                        "pending": store.counts(user, lambda p: False).get(page, {}).get("pending", 0)}
        return store.hold(user, perms, page, parts, change, describe_change(parts, change))
    if len(route) == 3 and route[1] in PAGES and route[2] in ("drop", "discard", "apply"):
        if route[2] == "drop":
            return store.drop(user, route[1], str(body.get("id", "")) or "-")
        if route[2] == "discard":
            return store.drop(user, route[1])
        return store.apply(user, perms, route[1], user, None)
    return None
