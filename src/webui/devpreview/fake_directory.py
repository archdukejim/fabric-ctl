from webui.devpreview.fabric_rules import ValidationError, check_password_policy, list_devices, read_policy_changes
from webui.devpreview.sample_data import SAMPLE_ACCESS, SAMPLE_DOMAIN, SAMPLE_GPO


def _in_fabric_group(groups):
    """Purpose: Whether a sample person holds a fabric group, which only an admin may change (as person_guard).
    Inputs:  groups — the person's group names.
    Returns: bool: any group but `users` and the site groups (`site-<name>`), which every person of a site is in.
    Fails:   never.
    Feeds:   _people."""
    return any(g != "users" and not g.startswith("site-") for g in groups)


def _people(state, who, route, body):
    """Purpose: People added, reset, disabled, enabled, removed or regrouped in memory, with the agent's refusals (a
             fabric-group member without system:admin; yourself; the user name not typed back; a taken name).
    Inputs:  state — DevState; who — the preview's person; route — ["people"] or ["people", <uid>, <op>]; body —
             dict.
    Returns: the agent's answer.
    Fails:   ValidationError with the agent's reason.
    Feeds:   fake_directory."""
    users = state.data["people"]["users"]
    if route == ["people"]:
        uid = str(body.get("uid", "")).strip()
        if not uid or any(u["uid"] == uid for u in users):
            raise ValidationError(f"{uid or 'a user name'} is missing or already exists")
        users.append({"uid": uid, "name": f"{body.get('first', '')} {body.get('last', '')}".strip(),
                      "mail": body.get("email", ""), "locked": False, "groups": ["site-lan", "users"],
                      "sites": ["lan"], "site": "lan"})
        state.log("PERSON_CREATE", f"user={uid} (dev preview)")
        return {"password": "dev-preview-not-real"}
    uid, op = route[1], route[2]
    target = next((u for u in users if u["uid"] == uid), None)
    if target is None:
        raise ValidationError(f"no person {uid} in this site")
    if _in_fabric_group(target["groups"]) and "system:admin" not in who["perms"]:
        raise ValidationError(f"{uid} is in a fabric group: only an admin can "
                              + ("reset their sign-in" if op == "reset" else "change them"))
    if op in ("disable", "delete") and uid == who["user"]:
        raise ValidationError(f"you cannot {'remove' if op == 'delete' else op} yourself")
    if op == "reset":
        state.log("PERSON_RESET", f"user={uid} (dev preview)")
        return {"password": "dev-preview-not-real"}
    if op == "delete":
        if str(body.get("confirm", "")).strip() != uid:
            raise ValidationError("type the user name to confirm")
        users.remove(target)
        state.log("PERSON_REMOVE", f"user={uid} (dev preview)")
        return {"revoked": []}
    if op == "groups":
        group, add = str(body.get("group", "")), body.get("action") == "add"
        before = set(target["groups"])
        target["groups"] = sorted(before | {group} if add else before - {group})
        return {"member": add, "group": group, "changed": set(target["groups"]) != before}
    if op in ("disable", "enable"):
        target["locked"] = op == "disable"
        state.log("PERSON_DISABLE" if op == "disable" else "PERSON_ENABLE", f"user={uid} (dev preview)")
        return {}
    return None


def _devices(state, route, body):
    """Purpose: Devices and device roles saved, deleted or a certificate unlinked, in memory, with fabriclib's rules.
    Inputs:  state — DevState; route — ["devices"|"roles"], [.., <name>], [.., <name>, "delete"], ["devices",
             <name>, "certs"]; body — {"name", "fields"} (the console's device and role fields), sha256, link.
    Returns: the agent's answer ({"name"} for a save, else {}).
    Fails:   ValidationError (fabriclib's checks; an existing name; a role still holding devices; no fabriclib).
    Feeds:   fake_directory."""
    if not list_devices:
        raise ValidationError("the dev preview from the image has no fabriclib; run it from a checkout")
    kind, d = route[0], state.data["directory"]
    if len(route) == 1:
        name = str(body.get("name", "")).strip().lower()
        if any(x["name"] == name for x in d[kind]):
            raise ValidationError(f"{name} already exists")
        state.save(kind, name, body.get("fields") or {})
        return {"name": name}
    name = route[1]
    if route[2:] == ["delete"]:
        if kind == "roles" and any(r["members"] for r in d["roles"] if r["name"] == name):
            raise ValidationError(f"role {name} still has devices; take them out first")
        d[kind] = [x for x in d[kind] if x["name"] != name]
        for r in d["roles"]:
            r["members"] = [m for m in r["members"] if m != name]
        return {}
    if route[2:] == ["certs"]:
        for x in d["devices"]:
            if x["name"] == name:
                x["certs"] = [c for c in x["certs"] if c != body.get("sha256")]
        return {}
    if len(route) == 2:
        state.save(kind, name, body.get("fields") or {})
        return {"name": name}
    return None


def _machines(state, route, body):
    """Purpose: Machines added, enabled, disabled or removed; host groups and sudo rules (1.6.11.7), in memory.
    Inputs:  state — DevState; route — ["machines"], ["machines", <name>, <op>], ["host-groups"…], ["sudo"…];
             body — dict.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError for an unknown machine or group, or a name already taken.
    Feeds:   fake_directory."""
    machines, groups, rules = SAMPLE_DOMAIN["machines"], SAMPLE_ACCESS["groups"], SAMPLE_ACCESS["sudo"]
    if route == ["machines"]:
        name = str(body.get("name", "")).strip().lower()
        if not name or any(m["name"] == name for m in machines):
            raise ValidationError(f"{name or 'a name'} is missing or already taken")
        machines.append({"name": name, "dns": f"{name}.ad.home.arpa", "os": "", "enabled": True, "last_logon": "",
                         "created": "today", "dn": ""})
        return {"password": "dev-preview-not-real"}
    if len(route) == 3 and route[0] == "machines":
        m = next((x for x in machines if x["name"] == route[1]), None)
        if m is None:
            raise ValidationError(f"no machine {route[1]}")
        if route[2] == "delete":
            machines.remove(m)
        elif route[2] in ("enable", "disable"):
            m["enabled"] = route[2] == "enable"
        else:
            return None
        return {}
    if route == ["host-groups"]:
        name = "hosts-" + str(body.get("name", "")).strip().lower()
        groups.append({"name": name, "short": name[6:], "machines": [], "other_members": [], "rules": [],
                       "hosts": [], "fabric": True})
        return {"name": name}
    if len(route) == 3 and route[0] == "host-groups":
        g = next((x for x in groups if x["name"] == route[1]), None)
        if g is None:
            raise ValidationError(f"no host group {route[1]}")
        if route[2] == "delete":
            groups.remove(g)
            return {"name": g["name"]}
        machine, add = str(body.get("machine", "")), body.get("action") == "add"
        before = set(g["machines"])
        g["machines"] = sorted(before | {machine} if add else before - {machine})
        return {"machine": machine, "group": g["name"], "member": add, "changed": set(g["machines"]) != before}
    if route == ["sudo"]:
        name = str(body.get("name", "")).strip()
        rules.append({"name": name, "kind": "fabric", "users": body.get("users") or [],
                      "commands": body.get("commands") or [], "run_as": body.get("run_as") or ["root"],
                      "hosts": [], "host_group": body.get("hosts", "")})
        return {"name": name, "hosts": []}
    if len(route) == 3 and route[0] == "sudo" and route[2] == "delete":
        SAMPLE_ACCESS["sudo"] = [r for r in rules if r["name"] != route[1]]
        return {"name": route[1]}
    return None


def _policy(state, route, body):
    """Purpose: The password policy (checked by fabriclib's own rules, as the agent does) and Group Policy, in memory.
    Inputs:  state — DevState; route — ["domain", "password-policy"] or ["gpo", "search"|"set"|"clear"]; body — dict.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError (a policy value; no fabriclib).
    Feeds:   fake_directory."""
    if route == ["domain", "password-policy"]:
        if not read_policy_changes:
            raise ValidationError("the dev preview from the image has no fabriclib; run it from a checkout")
        policy = {**SAMPLE_DOMAIN["policy"], **read_policy_changes(body)}
        check_password_policy(policy)
        SAMPLE_DOMAIN["policy"] = policy
        state.log("AD_PASSWORD_POLICY", "(dev preview: in memory)")
        return {"policy": policy}
    if route == ["gpo", "search"]:
        match = str(body.get("match", "")).lower()
        return {**SAMPLE_GPO, "match": match,
                "policies": [p for p in SAMPLE_GPO["policies"] if match in (p["name"] + p["display"]).lower()]}
    if route in (["gpo", "set"], ["gpo", "clear"]):
        state.log("GPO_" + route[1].upper(), f"{body.get('policy', '')} (dev preview: in memory)")
        return {"changed": [f"{route[1]} {body.get('policy', '')} (dev preview: nothing written)"]}
    return None


def fake_directory(state, who, route, body):
    """Purpose: The fake agent's directory changes: people, 802.1X devices and roles, machines, host groups, sudo
             rules, the password policy and Group Policy — in memory.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict.
    Returns: the agent's answer, or None for a route that is not the directory's.
    Fails:   ValidationError with the agent's reasons.
    Feeds:   fake_agent."""
    area = route[:1]
    if area == ["people"] and (len(route) == 1 or len(route) == 3):
        return _people(state, who, route, body)
    if area in (["devices"], ["roles"]):
        return _devices(state, route, body)
    if area in (["machines"], ["host-groups"], ["sudo"]):
        return _machines(state, route, body)
    if area in (["domain"], ["gpo"]):
        return _policy(state, route, body)
    return None
