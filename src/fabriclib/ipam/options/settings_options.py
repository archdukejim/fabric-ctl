KINDS = ("options", "option_defs", "client_classes")


def settings_options(v):
    """Purpose: the options, definitions and classes this site's settings still carry (not moved into the plan yet,
             manual 1.10.4.24.4), as effective_options takes them.
    Inputs:  v — fabric vars (dhcp).
    Returns: {"options", "option_defs", "client_classes"} or None when it carries none.
    Fails:   never.
    Feeds:   options_overview, networks_view (this install's site only)."""
    d = v.get("dhcp") or {}
    out = {k: list(d.get(k) or []) for k in KINDS}
    return out if any(out.values()) else None
