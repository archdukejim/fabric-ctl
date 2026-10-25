import re

from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.sample_data import SAMPLE_ACCESS, SAMPLE_DIRECTORY, SAMPLE_DOMAIN

FOLDERS = {"server": "machines/servers", "desktop": "machines/desktops", "network": "machines/network"}
# the preview's grants on its computers, in reaching_grants' shape: the servers' shipped grant reaches the servers
SAMPLE_REACHING = {"server": [{"name": "server-administrators", "kind": "allow",
                               "description": "the servers' administrators (manual 1.6.13.5)", "who": ["server-admins"],
                               "people": 1, "rights": {"people": [], "machines": [], "signin": ["keyboard", "remote"],
                                                       "sudo": ["ALL"], "local_admin": True}}],
                   "desktop": [{"name": "desktops", "kind": "allow",
                                "description": "every person signs in at the desktops (manual 1.6.13.5)",
                                "who": ["Domain Users"], "people": 3,
                                "rights": {"people": [], "machines": [], "signin": ["keyboard"], "sudo": [],
                                           "local_admin": False}}]}


def _rows():
    """Purpose: The preview's computers as GET /v1/machines answers: each with its machine groups (the sample machine
             groups holding it).
    Inputs:  none.
    Returns: list of dicts, by name.
    Fails:   never.
    Feeds:   fake_machines."""
    return [{**m, "type": m.get("type", ""), "sites": list(m.get("sites") or []), "folder": m.get("folder", "machines"),
             "groups": sorted(g["name"] for g in SAMPLE_ACCESS["groups"] if m["name"] in g["machines"])}
            for m in sorted(SAMPLE_DOMAIN["machines"], key=lambda x: x["name"])]


def _machine(name):
    """Purpose: One preview computer's stored row.
    Inputs:  name — its host name.
    Returns: the row (in SAMPLE_DOMAIN, changed in place).
    Fails:   ValidationError "no machine <name> in the domain" (as the agent).
    Feeds:   fake_machines."""
    row = next((m for m in SAMPLE_DOMAIN["machines"] if m["name"] == str(name).lower()), None)
    if row is None:
        raise ValidationError(f"no machine {name} in the domain")
    return row


def _overview(state, name):
    """Purpose: One computer as GET /v1/machines/<name> answers (manual 1.6.12.6).
    Inputs:  state — DevState (the 802.1X devices); name — its host name.
    Returns: {"machine", "grants", "devices", "choices"}.
    Fails:   ValidationError "no machine <name> in the domain".
    Feeds:   fake_machines."""
    _machine(name)
    row = next(m for m in _rows() if m["name"] == str(name).lower())
    devices = [{k: d.get(k) for k in ("name", "type", "enabled", "macs", "roles", "vlan")}
               for d in (state.overview() or {}).get("devices", []) if str(d.get("name", "")).lower() == row["name"]]
    return {"machine": row, "grants": [dict(g) for g in SAMPLE_REACHING.get(row["type"], [])], "devices": devices,
            "choices": {"sites": list(SAMPLE_DIRECTORY["sites"]),
                        "groups": sorted(g["name"] for g in SAMPLE_ACCESS["groups"]),
                        "folders": sorted({"machines", *FOLDERS.values(), "machines/servers/web"})}}


def _keytab(name, body):
    """Purpose: A service's keytab command (manual 1.6.12.17.8), checked as the agent checks it.
    Inputs:  name — the computer; body — {"service", "user", "path"}.
    Returns: {"machine", "command", "spns"} (nothing changed).
    Fails:   ValidationError for the machine's own classes, a bad user or path.
    Feeds:   fake_machines."""
    row = _machine(name)
    service, user, path = (str(body.get(k) or "") for k in ("service", "user", "path"))
    if service.lower() in ("host", "restrictedkrbhost", "cifs") or not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,31}$",
                                                                                   service):
        raise ValidationError(f"service: a service class that is not the machine's own (host, RestrictedKrbHost, "
                              f"cifs), not {service!r}")
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", user):
        raise ValidationError(f"user: a local user name, not {user!r}")
    if path and (not path.startswith("/") or path == "/etc/krb5.keytab"):
        raise ValidationError("path: an absolute path that is not the machine's own keytab")
    command = f"sudo fabric-keytab --machine {row['name']} --service {service} --user {user}"
    return {"machine": row["name"], "command": command + (f" --path {path}" if path else ""),
            "spns": [f"{service}/{row['dns']}", f"{service}/{row['name'].upper()}"]}


def fake_machines(state, who, route, body):
    """Purpose: The fake agent's computers (manual 1.6.12.6): GET /v1/machines and /v1/machines/<name>; POST
             /v1/machines/<name>/type, /sites, /move and /keytab — in memory (add, enable, disable and remove are
             fake_directory's).
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict, or None for a read.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the agent's reasons (no such machine, a type, site or folder refused).
    Feeds:   fake_agent."""
    if route[:1] != ["machines"]:
        return None
    if body is None:
        if route == ["machines"]:
            return _rows()
        return _overview(state, route[1]) if len(route) == 2 else None
    if len(route) != 3 or route[2] not in ("type", "sites", "move", "keytab"):
        return None
    if route[2] == "keytab":
        return _keytab(route[1], body)
    row = _machine(route[1])
    if route[2] == "type":
        kind = str(body.get("type") or "")
        if kind not in FOLDERS:
            raise ValidationError(f"type: one of {', '.join(FOLDERS)}, not {kind!r}")
        changed = row.get("type") != kind
        row["type"] = kind
        if body.get("move") is True:
            row["folder"] = FOLDERS[kind]
        return {"name": row["name"], "type": kind, "changed": changed, "kept_folder": body.get("move") is not True}
    if route[2] == "sites":
        site, add = str(body.get("site") or ""), body.get("action") == "add"
        if body.get("action") not in ("add", "remove"):
            raise ValidationError("action: add or remove")
        if site not in SAMPLE_DIRECTORY["sites"]:
            raise ValidationError(f"no site {site}")
        before = set(row.get("sites") or [])
        row["sites"] = sorted(before | {site} if add else before - {site})
        return {"name": row["name"], "site": site, "member": add, "changed": set(row["sites"]) != before}
    path = str(body.get("path") or "")
    if path not in _overview(state, row["name"])["choices"]["folders"]:
        raise ValidationError(f"only to a folder under OU=machines: no OU {path or '(none)'}")
    changed, row["folder"] = row.get("folder") != path, path
    return {"name": row["name"], "path": path, "changed": changed}
