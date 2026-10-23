from webui import agentclient as actions
from webui import views
from webui.session.page_context import page_context


def radius_post(h, sess, parts, form):
    """Purpose: RADIUS clients: add, new shared secret, remove — saved and applied at once; a secret is shown once on
             its own page, never in a URL.
    Inputs:  h — the request handler (send, back, deny); sess — dict from find_session; parts — path segments after
             /freeradius/clients: [] add (form: name, lower-cased; address; message_authenticator '1' to require it;
             secret, optional), [<name>, 'rotate'], [<name>, 'delete']; form — dict from read_form.
    Returns: add / rotate: 200 page with the shared secret, the RADIUS host IP and whether applying worked; delete: 303
             to /8021x with what was done, or why applying failed, as its message.
    Fails:   404 for other paths; ValidationError → 303 to /8021x with the refusal; AgentError, PermissionDenied and
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
            res = actions.remove_radius_client(parts[0])
            msg = f"RADIUS client {parts[0]} removed."
            if not res.get("applied"):
                return h.back("/8021x", err=msg + " Saved, but applying failed: " + res.get("output", "")[-300:])
            return h.back("/8021x", msg=msg)
        else:
            return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        return h.back("/8021x", err=str(exc))
    host_ip = (actions.radius_overview() or {}).get("host_ip", "")
    return h.send(200, views.radius_secret(page_context(sess), name, res.get("secret", ""), action, host_ip,
                                           bool(res.get("applied")), res.get("output", "")))
