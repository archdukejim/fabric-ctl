import re

from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.fake_job import fake_job

SECTIONS = [
    {"name": "settings", "what": "vars.yaml (all of it), fabric's config, the audit log, federation's registry, "
                                 "the run "
                                 "records", "depends": [], "alone": True},
    {"name": "pki", "what": "Step-CA whole (root and intermediate keys, its database) and every issued certificate and "
                            "key", "depends": [], "alone": True},
    {"name": "secrets", "what": "OpenBao's data, its vault key and unlock-method files",
     "depends": ["settings", "pki", "directory", "dns", "signin", "dhcp"], "alone": False},
    {"name": "directory", "what": "the domain: Samba's database and SYSVOL (people, groups, machines, devices, "
                                  "policies, the address plan)", "depends": ["dns", "dhcp"], "alone": True},
    {"name": "dns", "what": "BIND's zones and keys, the resolver, the DNS filter and AdGuard Home's settings",
     "depends": [], "alone": True},
    {"name": "signin", "what": "Keycloak's database (people's second factors, sessions, the realm)", "depends": [],
     "alone": True},
    {"name": "dhcp", "what": "Kea's leases and its settings", "depends": [], "alone": True}]
ALL = [s["name"] for s in SECTIONS]


def _bundle(when, kind, size, version, check="whole", opened_by="passphrase"):
    """Purpose: one sample bundle row, as list_bundles and the agent's check give it.
    Inputs:  when — yyyymmddThhmmssZ; kind; size — bytes; version; check; opened_by.
    Returns: dict.
    Fails:   never.
    Feeds:   _state."""
    return {"file": f"fabric-fabric-{when}-{kind}.fabric.tar", "kind": kind, "when": when, "size": size,
            "fabric_version": version, "host": "fabric", "sections": ALL, "error": None, "check": check,
            "opened_by": opened_by, "method": "online"}


def _state(state):
    """Purpose: the preview's backups, made the first time they are read.
    Inputs:  state — DevState.
    Returns: {"bundles", "schedule"}.
    Fails:   never.
    Feeds:   fake_backup."""
    return state.data.setdefault("backup", {
        "bundles": [_bundle("20261122T030000Z", "scheduled", 412 * 2**20, "0.10.1", opened_by="age1qyqszqgpqyqszqgp"),
                    _bundle("20261121T150412Z", "manual", 398 * 2**20, "0.10.1"),
                    _bundle("20261120T030000Z", "scheduled", 405 * 2**20, "0.10.0", "checking", ""),
                    _bundle("20261118T091500Z", "uninstall", 377 * 2**20, "0.10.0",
                            "dns.tar.zst.age: its SHA-256 differs from the manifest's (the file was changed or cut "
                            "short)", "")],
        "schedule": {"on": True, "time": "03:00", "keep": 7, "public_key": "age1qyqszqgpqyqszqgp",
                     "next": "Mon 2026-11-23 03:00:00 UTC", "last": "Sun 2026-11-22 03:00:00 UTC",
                     "last_result": "ok"}})


def fake_backup(state, who, route, body):
    """Purpose: the fake agent's backup routes (manual 1.3.7.9): the list, a download, Back up now, the schedule, a
             section restored — in memory, nothing made or restored.
    Inputs:  state — DevState; who — the preview's person; route — segments after /v1/; body — dict (None or {} for a
             read).
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the agent's reasons.
    Feeds:   fake_agent."""
    if route[:1] != ["backup"]:
        return None
    data = _state(state)
    if route == ["backup", "allowed"]:
        return {"allowed": True}
    if route == ["backup"]:
        return {"bundles": data["bundles"], "schedule": data["schedule"], "running": False, "site": "lan",
                "console_restore": data.get("console_restore") or {"running": False, "tail": ""},
                "version": "0.10.1", "sections": SECTIONS}
    if len(route) == 3 and route[1] == "bundles":
        if route[2] not in {b["file"] for b in data["bundles"]}:
            raise ValidationError(f"no bundle {route[2]}")
        return "the preview's sample: a real download is the encrypted bundle itself"
    if route == ["backup", "now"]:
        if not body.get("scheduled_key") and len(body.get("passphrase") or "") < 12:
            raise ValidationError("a passphrase of 12 characters or more: nothing was made")
        return fake_job(state, "backup", {"message": "Bundle made (in the preview: nothing was made)."})
    if route == ["backup", "schedule"]:
        if body.get("off"):
            data["schedule"].update(on=False, public_key="", next="", last="", last_result="")
        else:
            key = body.get("public_key") or data["schedule"]["public_key"]
            if not key.startswith("age1"):
                raise ValidationError("public_key: an age public key (age1…)")
            data["schedule"].update(on=True, time=body.get("time") or "03:00", keep=int(body.get("keep") or 7),
                                    public_key=key)
        s = data["schedule"]
        return {"schedule": f"on {s['time']}" if s["on"] else "off", "time": s["time"], "keep": s["keep"],
                "public_key": s["public_key"]}
    if route == ["backup", "restore"]:
        if body.get("confirm") != "lan":
            raise ValidationError(f"type the site's name (lan) to restore {body.get('section')}: nothing changed")
        if not body.get("key"):
            raise ValidationError("key: the bundle's passphrase, or the schedule's private key (AGE-SECRET-KEY-1…)")
        return fake_job(state, "restore", {"message": f"{body.get('section')} restored from {body.get('file')} (in "
                                                      "the preview: nothing was restored)."})
    if route == ["backup", "upload"]:
        name = body.get("name") or ""
        if not re.fullmatch(r"fabric-[A-Za-z0-9-]+-\d{8}T\d{6}Z-[a-z]+\.fabric\.tar", name):
            raise ValidationError("the file's name is not a bundle's (fabric-<host>-<when>-<kind>.fabric.tar): keep "
                                  "the name it was downloaded with")
        if name in {b["file"] for b in data["bundles"]}:
            raise ValidationError(f"{name} is already in the backups folder")
        if not body.get("head", "").startswith("manifest.json"):
            raise ValidationError("not a bundle: it has no manifest.json")
        when = name.rsplit("-", 2)
        data["bundles"].insert(0, dict(_bundle(when[-2], when[-1].split(".")[0], body["size"], "0.10.1"), file=name))
        return {"file": name, "size": body["size"]}
    if route == ["backup", "reinstall"]:
        if body.get("confirm") != "lan":
            raise ValidationError("type the site's name (lan) to restore the whole bundle: nothing changed")
        if not body.get("key"):
            raise ValidationError("key: the bundle's passphrase, or the schedule's private key (AGE-SECRET-KEY-1…)")
        data["console_restore"] = {"running": True, "tail": f"Restore {body.get('file')} in place of this install "
                                                            "(in the preview: nothing is restored)\n"}
        return {"started": True, "unit": "fabric-console-restore"}
    return None
