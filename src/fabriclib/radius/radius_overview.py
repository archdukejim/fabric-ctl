from fabriclib.radius.list_auth_log import list_auth_log
from fabriclib.radius.nas.profiles import PROFILES, VENDORS


def radius_overview(v, log_limit=50):
    """Purpose: What the FreeRADIUS tab and `fabricctl radius status` show. Read-only.
    Inputs:  v — the vars dict (install_freeradius, hostname_radius, host_ip, radius_clients, radius_people).
             log_limit — how many recent decisions to read (default 50).
    Returns: {"enabled", "server_name", "host_ip", "clients": [{"name", "address", "message_authenticator", "vendor",
             "transport", "coa" (its vendor has CoA)}] (never secrets), "vendors" (the vendor names, for the form),
             "people": [{"group", "vlan", "priority"}], "log" (see list_auth_log), "log_error"}.
    Fails:   never for the journal — any error reading it goes into log_error.
    Feeds:   agent route GET /v1/radius (fabric-agent, src/agent/, called by the web UI); run_radius_command
             (status, with log_limit=0).
    """
    on = bool(v.get("install_freeradius"))
    out = {"enabled": on, "server_name": v.get("hostname_radius", ""), "host_ip": v.get("host_ip", ""),
           "clients": [{"name": c.get("name"), "address": c.get("address"),
                        "message_authenticator": c.get("message_authenticator", True),
                        "vendor": c.get("vendor", "generic"), "transport": c.get("transport", "udp"),
                        "coa": bool(PROFILES.get(c.get("vendor", "generic"), {}).get("coa"))}
                       for c in v.get("radius_clients") or []],
           "people": [{"group": m.get("group"), "vlan": m.get("vlan"), "priority": m.get("priority", 100)}
                      for m in v.get("radius_people") or []],
           "vendors": list(VENDORS), "log": [], "log_error": ""}
    if on:
        try:
            out["log"] = list_auth_log(log_limit)
        except Exception as exc:          # journal unreadable: the tab still shows the rest
            out["log_error"] = f"the auth log could not be read: {exc}"
    return out
