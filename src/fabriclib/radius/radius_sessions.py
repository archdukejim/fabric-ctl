from fabriclib.radius.list_radius_sessions import list_radius_sessions
from fabriclib.radius.nas.nas_profile import nas_profile
from fabriclib.radius.nas.profiles import DEFAULT_VENDOR


def radius_sessions(v, records=None):
    """Purpose: what the FreeRADIUS tab's Sessions view and `fabricctl radius sessions` show: the open sessions,
             each with what its client's vendor lets fabric do to it (manual 1.11.1.4). Read-only.
    Inputs:  v — the vars dict (install_freeradius, radius_clients); records — passed to list_radius_sessions (None:
             the journal).
    Returns: {"enabled", "sessions": [list_radius_sessions' entries + "vendor", "actions" (the CoA actions its
             profile has: disconnect, reauthenticate, bounce; [] for none or a client no longer listed),
             "no_coa" (why not, "" when actions)], "error"}.
    Fails:   never for the journal: an error reading it goes into "error".
    Feeds:   agent route GET /v1/radius/sessions (fabric-agent, called by the web UI); run_radius_command
             (sessions).
    """
    out = {"enabled": bool(v.get("install_freeradius")), "sessions": [], "error": ""}
    if not out["enabled"]:
        return out
    clients = {c.get("name"): c for c in v.get("radius_clients") or []}
    try:
        found = list_radius_sessions(records)
    except Exception as exc:              # journal unreadable: the page still shows why
        out["error"] = f"the accounting log could not be read: {exc}"
        return out
    for s in found:
        client = clients.get(s["client"])
        if client is None:
            out["sessions"].append({**s, "vendor": "-", "actions": [],
                                    "no_coa": "its RADIUS client is no longer listed"})
            continue
        profile = nas_profile(client.get("vendor") or DEFAULT_VENDOR)
        actions = sorted((profile["coa"] or {}).get("actions", {}))
        out["sessions"].append({**s, "vendor": profile["vendor"], "actions": actions,
                                "no_coa": "" if actions else profile["no_coa"]})
    return out
