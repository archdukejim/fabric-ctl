from webui import agentclient as actions
from webui import views
from webui.routes.held import held, q
from webui.session.page_context import page_context


def radius_post(h, sess, parts, form):
    """Purpose: RADIUS clients: add and new shared secret saved and applied at once (they carry the secret, 2.1.8.17;
             it is shown once on its own page, never in a URL); remove held for the RADIUS clients page's Apply.
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; parts — path segments after
             /freeradius/clients: [] add (form: name, lower-cased; address; message_authenticator '1' to require it;
             secret, optional), [<name>, 'rotate'], [<name>, 'delete']; form — dict from read_form.
    Returns: add / rotate: 200 page with the shared secret, the RADIUS host IP and whether applying worked; delete: 303
             to /8021x saying it waits for Apply, or why not.
    Fails:   404 for other paths; ValidationError → 303 with the refusal (the client's page, or /8021x for one not
             there); AgentError, PermissionDenied and
             AuthError propagate to handle_request.
    Feeds:   post_action (/freeradius/clients…).
    """
    try:
        if not parts:
            name = form.get("name", "").strip().lower()
            res = actions.add_radius_client(name, form.get("address", ""),
                                            form.get("message_authenticator") == "1", form.get("secret", ""))
            action = "added"
        elif len(parts) == 2 and parts[1] == "rotate":
            name, action = parts[0], "rotated"
            res = actions.rotate_radius_secret(name)
        elif len(parts) == 2 and parts[1] == "delete":
            return held(h, "/8021x", f"radius/clients/{q(parts[0])}/delete", {})
        else:
            return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        back = "/8021x/clients/_new"
        if parts:                            # a client that is not there: its page answers 404 (2.1.8.16), so the list
            known = any(c.get("name") == parts[0] for c in (actions.radius_overview() or {}).get("clients") or [])
            back = f"/8021x/clients/{q(parts[0])}" if known else "/8021x"
        return h.back(back, err=str(exc))
    host_ip = (actions.radius_overview() or {}).get("host_ip", "")
    return h.send(200, views.radius_secret(page_context(sess), name, res.get("secret", ""), action, host_ip,
                                           bool(res.get("applied")), res.get("output", "")))
