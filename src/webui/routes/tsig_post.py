import re

from webui import agentclient as actions
from webui import views
from webui.routes.bind9_page import bind9_page
from webui.routes.held import held, q
from webui.session.page_context import page_context


def _edit(form):
    """Purpose: Edit names' form as the agent's edit body (decision 2.1.4.13, manual 1.4.1.9.1): one Remove, one
             Add (a record of the zone, with or without its aliases, or a name typed in), or a Custom key's scope
             and record types.
    Inputs:  form — dict: drop | drop_with_aliases (a name), pick ("rec:<name>" or "ali:<name>"), typed (a name),
             set_scope with scope and type_<T> checkboxes.
    Returns: the body for POST /v1/tsig/<name>/update ({} when the form names nothing: the agent then says
             "nothing to change").
    Fails:   never (the agent checks every name).
    Feeds:   tsig_post (update)."""
    body = {}
    if form.get("drop"):
        body["drop"] = [form["drop"]]
    if form.get("drop_with_aliases"):
        body["drop_with_aliases"] = [form["drop_with_aliases"]]
    kind, _, name = (form.get("pick") or "").partition(":")
    if name and kind in ("rec", "ali"):
        body["add" if kind == "rec" else "add_with_aliases"] = [name]
    if (form.get("typed") or "").strip():
        body.setdefault("add", []).append(form["typed"].strip())
    if form.get("set_scope"):
        body["scope"] = form.get("scope", "")
        body["record_types"] = [t for t in actions.RECORD_TYPES if form.get(f"type_{t}")]
    return body


def tsig_post(h, sess, rest, form):
    """Purpose: TSIG keys: create and rotate at once (they make a secret, 2.1.8.17: BIND takes it at once); Edit
             names and delete held for DNS' Apply (2.1.8.18; Edit names 2.1.4.13).
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; rest — str after
             /bind9/tsig/ (unquoted): 'create' (form name, zone, scope — 'acme' (ACME (DNS-01) mode, 2.1.4.12:
             rec_<name> and ali_<name> checkboxes for the zone's records, with_aliases 2.1.4.14) or Custom's
             scopes with hosts space/comma separated and type_<T> checkboxes; secret — optional existing one),
             '<name>/rotate', '<name>/update' (_edit's fields), '<name>/delete'; form — dict.
    Returns: create / rotate: 200 page with the secret and an RFC2136 ini (shown once), and BIND's refusal when it
             did not take the key; update: 303 to the key's page saying it waits for Apply, or the refusal (nothing
             held; to the TSIG list for a key no longer there, whose page would answer 404); delete: 303 to
             /dns/zones?view=tsig saying it waits for Apply, or the refusal.
    Fails:   404 for anything else; ValidationError → the TSIG section again with 400 and the error; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/tsig/…).
    """
    ctx, user = page_context(sess), sess["user"]
    name, _, op = rest.rpartition("/")
    back = {"view": "tsig"}
    try:
        if rest == "create":
            if form.get("scope") == "acme":               # ACME (DNS-01): the zone's records picked (2.1.4.12)
                hosts = [k[len("rec_"):] for k, v in form.items() if k.startswith("rec_") and v]
                with_aliases = [k[len("ali_"):] for k, v in form.items() if k.startswith("ali_") and v]
                back = {"view": "newkey", "mode": "acme", "zone": form.get("zone", "")}
                r = actions.create_tsig_key(user, form.get("name", ""), form.get("zone", ""), "acme", hosts,
                                            ["TXT"], form.get("secret", ""), with_aliases)
            else:
                hosts = [x for x in re.split(r"[\s,]+", form.get("hosts", "")) if x]
                types = [t for t in actions.RECORD_TYPES if form.get(f"type_{t}")]
                back = {"view": "newkey", "mode": "custom"}
                r = actions.create_tsig_key(user, form.get("name", ""), form.get("zone", ""), form.get("scope", ""),
                                            hosts, types, form.get("secret", ""))
            return h.send(200, views.tsig_result(ctx, r["key"]["name"], r["secret"], r["ini"], "created",
                                                 r.get("publish_error", "")))
        if op == "rotate":
            r = actions.rotate_tsig_key(user, name)
            return h.send(200, views.tsig_result(ctx, name, r["secret"], r["ini"], "rotated",
                                                 r.get("publish_error", "")))
        if op == "update":                   # Edit names: held for DNS' Apply, the secret kept (2.1.4.13)
            gone = not any(k.get("name") == name for k in actions.list_tsig_keys())
            page = "/dns/zones?view=tsig" if gone else "/dns/zones?view=key&key=" + q(name)   # a gone key's page: 404
            return held(h, page, f"tsig/{q(name)}/update", _edit(form))
        if op == "delete":                   # held for DNS' Apply (2.1.8.18); creating and rotating are at once
            return held(h, "/dns/zones?view=tsig", f"tsig/{q(name)}/delete", {})
        return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        ctx["flash"] = {"err": str(exc)}
        return bind9_page(h, ctx, back, status=400)
