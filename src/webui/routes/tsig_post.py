import re

from webui import agentclient as actions
from webui import views
from webui.routes.bind9_page import bind9_page
from webui.routes.held import held, q
from webui.session.page_context import page_context


def tsig_post(h, sess, rest, form):
    """Purpose: TSIG keys: create and rotate at once (they make a secret, 2.1.8.17: BIND takes it at once), delete
             held for DNS' Apply (2.1.8.18).
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; rest — str after
             /bind9/tsig/ (unquoted): 'create' (form name, zone, scope, hosts space/comma separated, type_<T>
             checkboxes, secret — optional existing one), '<name>/rotate', '<name>/delete'; form — dict.
    Returns: create / rotate: 200 page with the secret and an RFC2136 ini (shown once), and BIND's refusal when it
             did not take the key; delete: 303 to /dns/zones?view=tsig saying it waits for Apply, or the refusal.
    Fails:   404 for anything else; ValidationError → the TSIG section again with 400 and the error; AgentError,
             PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/tsig/…).
    """
    ctx, user = page_context(sess), sess["user"]
    name, _, op = rest.rpartition("/")
    back = {"view": "tsig"}
    try:
        if rest == "create":
            hosts = [x for x in re.split(r"[\s,]+", form.get("hosts", "")) if x]
            types = [t for t in actions.RECORD_TYPES if form.get(f"type_{t}")]
            r = actions.create_tsig_key(user, form.get("name", ""), form.get("zone", ""), form.get("scope", ""),
                                        hosts, types, form.get("secret", ""))
            return h.send(200, views.tsig_result(ctx, r["key"]["name"], r["secret"], r["ini"], "created",
                                                 r.get("publish_error", "")))
        if op == "rotate":
            r = actions.rotate_tsig_key(user, name)
            return h.send(200, views.tsig_result(ctx, name, r["secret"], r["ini"], "rotated",
                                                 r.get("publish_error", "")))
        if op == "delete":                   # held for DNS' Apply (2.1.8.18); creating and rotating are at once
            return held(h, "/dns/zones?view=tsig", f"tsig/{q(name)}/delete", {})
        return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        ctx["flash"] = {"err": str(exc)}
        return bind9_page(h, ctx, back, status=400)
