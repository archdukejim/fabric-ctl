from webui.routes.held import held
from webui.routes.picked_record import picked_record

BACK = "/dns/zones?view=landing"


def landing_post(h, user, parts, form):
    """Purpose: The landing page's own section of the DNS tab (manual 1.4.2.4, 2.1.2.22 item 4): link a record of the
             site's zone from the landing page, or stop linking it; held for DNS' Apply, which also writes the landing
             page (decisions 2.1.8.18, 2.1.8.24).
    Inputs:  h — the request handler (back, deny); user — the signed-in person (unused: the hold is the session's);
             parts — segments after /bind9/landing/: ["add"] (form record "<type>|<index>|<name>", link_label,
             link_port, link_path) or ["remove"] (form record, or type, index, name); form — dict.
    Returns: 303 back to /dns/zones?view=landing saying it waits for Apply, or the refusal (no record picked); the
             agent's own refusals (a bad label, port or path, a record changed since it was shown) come at Apply.
    Fails:   404 for another operation; AgentError, PermissionDenied and AuthError propagate to handle_request.
    Feeds:   post_action (/bind9/landing/…)."""
    rtype, index, name = picked_record(form)
    if parts == ["add"]:
        fields = {"link": "on", **{k: form.get(k, "") for k in ("link_label", "link_port", "link_path")}}
    elif parts == ["remove"]:
        fields = {"link": ""}
    else:
        return h.deny(404, "Not found.")
    if not rtype or not index.isdigit():
        return h.back(BACK, err="pick a record to link")
    return held(h, BACK, "zones/dynamic_zone_var/records/link",
                {"type": rtype, "index": int(index), "name": name, **fields})
