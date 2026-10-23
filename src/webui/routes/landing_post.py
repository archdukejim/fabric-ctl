from webui import agentclient as actions

BACK = "/dns/zones?view=landing"


def landing_post(h, user, parts, form):
    """Purpose: The landing page's own section of the DNS tab (manual 1.4.2.4, 2.1.2.22 item 4): link a record of the
             site's zone from the landing page, or stop linking it (published by the next Apply).
    Inputs:  h — the request handler (back, deny); user — the signed-in person; parts — segments after
             /bind9/landing/: ["add"] (form record "<type>|<index>|<name>", link_label, link_port, link_path) or
             ["remove"] (form type, index, name); form — dict.
    Returns: 303 back to /dns/zones?view=landing with what was done as its message, or the refusal on a
             ValidationError (a record not picked, a bad label, port or path, a record changed since it was shown).
    Fails:   404 for another operation; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/landing/…)."""
    if parts == ["add"]:
        rtype, _, rest = form.get("record", "").partition("|")
        index, _, name = rest.partition("|")
        fields = {**form, "link": "on"}
        done = "{name} is linked from the landing page. Apply to publish."
    elif parts == ["remove"]:
        rtype, index, name = form.get("type", ""), form.get("index", ""), form.get("name", "")
        fields = {"link": ""}
        done = "{name} is no longer linked from the landing page. Apply to publish."
    else:
        return h.deny(404, "Not found.")
    try:
        if not rtype or not index.isdigit():
            raise actions.ValidationError("pick a record to link")
        actions.set_record_link(user, "dynamic_zone_var", rtype, int(index), name, fields)
    except actions.ValidationError as exc:
        return h.back(BACK, err=str(exc))
    return h.back(BACK, msg=done.format(name=name))
