from webui import views
from webui.devpreview.sample_data import (RECORD_TYPES, SAMPLE_CA, SAMPLE_DEVICES, SAMPLE_DHCP, SAMPLE_DOMAIN,
                                          SAMPLE_FEDERATION, SAMPLE_GPO, SAMPLE_LOGON, SAMPLE_RADIUS, SAMPLE_ACME,
                                          SAMPLE_ACCESS,
                                          SAMPLE_IMAGES,
                                          SAMPLE_SECURITY, SAMPLE_VAULT, SAMPLE_DNS_FILTER, SAMPLE_QUERY_LOG)
from webui.devpreview.dev_settings import dev_settings
from webui.devpreview.sample_radius_guides import sample_radius_guides


def dev_get_page(h, path, query):
    """Purpose: Render the real pages (src/webui/views) with sample or in-memory data: /, /bind9, /stepca, /openbao,
             /directory, /kea, /dns-filter, /freeradius, /audit, /settings, /jobs/<id>, /static/app.css, and
             /preview/denied (what a refused sign-in looks like). No sign-in, no client certificate, no fabric-agent.
    Inputs:  h — the dev handler (send, state, ctx); path — the URL path; query — dict (msg, err, view, zone, device,
             slot, name; /dns-filter: wait, and fresh=1 for a fresh install's first fetch still running).
    Returns: None; sends 200 with the page, 403 for /preview/denied, 404 for anything else.
    Fails:   an exception from views or fabriclib is not caught: http.server logs it and closes the connection.
    Feeds:   dev_handler.DevHandler.do_GET (under the state lock)."""
    state, ctx = h.state, h.ctx
    if path == "/static/app.css":
        return h.send(200, views.css(), "text/css; charset=utf-8")
    if path == "/":
        return h.send(200, views.overview(ctx, state.data["services"], state.data["host_changes"],
                                             state.data.get("relaxed_settings", []),
                                             state.data.get("cert_warnings", []), SAMPLE_IMAGES,
                                             query.get("err", "")))
    if path.startswith("/jobs/"):
        job = state.data.setdefault("jobs", {}).get(path[len("/jobs/"):])
        if job is None:
            return h.send(400, views.error_page(400, "no such job"))
        return h.send(200, views.job_page(ctx, job))
    if path == "/bind9":
        section = query.get("view") if query.get("view") in ("landing", "reverse", "dhcp", "tsig") else "forward"
        key = "dynamic_zone_var" if section == "landing" else query.get("zone") or next(iter(state.data["zones"]))
        zone = state.zone(key) if section in ("forward", "landing") and key in state.data["zones"] else None
        return h.send(200, views.bind9(ctx, section, state.zones(), zone=zone, types=RECORD_TYPES,
                                       msg=query.get("msg", ""), err=query.get("err", ""),
                                       tsig_keys=state.data["tsig"] if section == "tsig" else None,
                                       reverse=state.reverse() if section == "reverse" else None,
                                       dhcp=SAMPLE_DHCP if section == "dhcp" else None))
    if path == "/stepca":
        view = query.get("view", "ca")
        view = view if view in views.STEPCA_VIEWS else "ca"
        ov = state.overview()
        return h.send(200, views.stepca(ctx, view, SAMPLE_CA, issued=state.data["issued"],
                                        devices=ov["devices"] if ov else [], device=query.get("device", ""),
                                        acme=SAMPLE_ACME if view == "acme" else None))
    if path == "/openbao":
        view = query.get("view") if query.get("view") in views.OPENBAO_VIEWS else "status"
        return h.send(200, views.openbao(ctx, SAMPLE_VAULT, view, state.data["slots"], SAMPLE_DEVICES,
                                         slot_id=query.get("slot", ""), host="pi-core", live=True,
                                         msg=query.get("msg", ""), err=query.get("err", ""),
                                         add_live={"security-key": True, "usb": True, "hsm": True}))
    if path == "/directory":
        view = query.get("view") if query.get("view") in ("device", "roles", "role", "people", "domain", "machines",
                                                          "gpo") else "devices"
        kw = {"msg": query.get("msg", ""), "err": query.get("err", "")}
        if view in ("domain", "machines"):
            return h.send(200, views.directory(ctx, view, domain=SAMPLE_DOMAIN, logon=SAMPLE_LOGON,
                                               access=SAMPLE_ACCESS, **kw))
        if view == "gpo":
            return h.send(200, views.directory(ctx, view, gpo={**SAMPLE_GPO, "match": query.get("match", "")}, **kw))
        if view == "people":
            return h.send(200, views.directory(ctx, view, people=state.data["people"], **kw))
        data = state.overview()
        if data is None:
            return h.send(200, views.directory(ctx, view, unavailable="dev preview from the image has no fabriclib; "
                                                                   "run it from a checkout", **kw))
        if view == "device":
            kw["device"] = next((d for d in data["devices"] if d["name"] == query.get("name")), None)
            view = view if kw["device"] else "devices"
        if view == "role":
            kw["role"] = next((r for r in data["roles"] if r["name"] == query.get("name")), None)
            view = view if kw["role"] else "roles"
        return h.send(200, views.directory(ctx, view, data=data, **kw))
    if path == "/federation":
        return h.send(200, views.federation(ctx, SAMPLE_FEDERATION))
    if path == "/dns-filter":
        view = query.get("view") if query.get("view") in [s for s, _ in views.DNS_FILTER_SECTIONS] else "overview"
        search = {k: query.get(k, "") for k in ("client", "name", "blocked", "limit")}
        log = SAMPLE_QUERY_LOG if view == "querylog" else None
        if log and search["blocked"] == "on":
            log = {"entries": [e for e in log["entries"] if e["blocked"]]}
        sample = SAMPLE_DNS_FILTER if not query.get("fresh") else {     # the lists job's first run not done yet
            **SAMPLE_DNS_FILTER, "catalogue_fetched": None, "categories": ["Added by URL"],
            "lists": [{**r, "last_fetch": None, "last_success": None, "rules": None, "memory_mb": None}
                      for r in SAMPLE_DNS_FILTER["lists"] if r["category"] == "Added by URL"]}
        return h.send(200, views.dns_filter(ctx, view, sample, log, search, query.get("msg", ""),
                                            query.get("err", ""), query.get("wait", 0)))
    if path == "/kea":
        # ?off=1: DHCP off, as a first turn-on shows it (manual 1.10.3.5); ?off=resume: off with settings kept
        sample = SAMPLE_DHCP if not query.get("off") else {
            **SAMPLE_DHCP, "enabled": False, "has_settings": query.get("off") == "resume", "leases": []}
        return h.send(200, views.kea(ctx, sample, query.get("msg", ""), query.get("err", "")))
    if path == "/freeradius":
        view = query.get("view", "overview")
        guides = sample_radius_guides() if view in ("switches", "windows") else None
        return h.send(200, views.freeradius(ctx, SAMPLE_RADIUS, query.get("msg", ""), query.get("err", ""), view,
                                            guides))
    if path == "/audit":
        return h.send(200, views.audit(ctx, state.data["audit"]))
    if path == "/security":
        return h.send(200, views.security(ctx, SAMPLE_SECURITY, query.get("msg", ""), query.get("err", "")))
    if dev_settings(h, "GET", path, query):     # the setup wizard (1.8.5.3) over sample data
        return None
    if path == "/preview/denied":       # what a refused sign-in looks like
        return h.send(403, views.error_page(403, "Your account is missing the 'fabric-console-admin' role."))
    return h.send(404, views.error_page(404, "Not found."))
