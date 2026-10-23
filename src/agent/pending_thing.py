import hashlib
import json

from fabriclib.common.errors import ValidationError

# The pages whose changes are held (manual 1.8.6.5, the Directory's first) and the permission that shows each page
# (who sees its queue). A page id is the console's navigation page (pending_page_of names it from the route).
PAGES = {"people": "people:read", "machines": "domain:read", "policies": "domain:read",
         "groups": "domain:read", "ous": "domain:read", "access": "domain:read", "kerberos": "domain:read",
         "devices": "devices:read", "roles": "devices:read", "account": "session"}
# a device's and a device role's own fields, as their read has them: what a change to one is checked against (what a
# role grants a device, its VLAN and permissions, follows from the roles and is not the device's own)
OWN_FIELDS = {"devices": ("type", "owner", "description", "macs", "enabled", "roles"),
              "roles": ("description", "vlan", "priority", "permissions")}
# the pages whose queue each person sees only their own applies of (My account, 1.8.6.6: nobody else's business)
OWN_QUEUE = {"account"}


def as_change(route):
    """Purpose: The route a held change is read and described as: a member change from My account
             (account/groups/<name>/members) is its group's members change.
    Inputs:  route — segments after /v1/.
    Returns: the segments (the same list for every other route).
    Fails:   never.
    Feeds:   describe_change, thing_state, thing_key."""
    if len(route) == 4 and route[:2] == ["account", "groups"] and route[3] == "members":
        return ["groups", route[2], "members"]
    return route

VERBS = {"reset": "Reset the sign-in of", "disable": "Disable", "enable": "Enable", "delete": "Remove",
         "unlock": "Unlock", "edit": "Edit", "move": "Move", "type": "Set the type of", "sites": "Change the sites of",
         "members": "Change the members of", "managers": "Change the managers of"}


def pending_page_of(route):
    """Purpose: The navigation page a change belongs to, for Apply per page (manual 1.8.6.5): decided by fabric-agent
             from the route, never by the caller.
    Inputs:  route — the change's route segments after /v1/ (e.g. ["people", "sam", "disable"]).
    Returns: a PAGES id ("people", "machines", ...), or None when the change is not held (it is done at once).
    Fails:   never.
    Feeds:   agent/post_pending (hold)."""
    head = route[:1]
    if as_change(route) is not route:
        return "account"
    if head == ["people"]:
        return "people"
    if head in (["machines"], ["host-groups"]) and route[-1:] != ["keytab"]:
        return "machines"
    if route == ["domain", "password-policy"] or head == ["sudo"]:      # Policies, one Apply (1.6.12.10)
        return "policies"
    if route == ["domain", "kerberos", "policy"]:
        return "kerberos"
    if route[:2] == ["domain", "grants"]:
        return "access"
    if route in (["gpo", "set"], ["gpo", "clear"]):
        return "policies"
    if head == ["groups"]:
        return "groups"
    if head == ["ous"]:
        return "ous"
    if head in (["devices"], ["roles"]):                 # 802.1X's Devices and Device roles (2.1.8.10)
        return head[0]
    return None


def describe_change(route, body):
    """Purpose: A change in a sentence, for the pending list and its queue ("Disable sam", "Add person dana").
    Inputs:  route — segments after /v1/; body — the change's JSON body.
    Returns: str.
    Fails:   never.
    Feeds:   agent/pending_store (hold)."""
    route = as_change(route)
    name = route[1] if len(route) > 1 else ""
    if len(route) == 1:
        what = {"people": "person", "machines": "machine", "host-groups": "machine group", "sudo": "sudo rule",
                "groups": "group", "ous": "OU", "devices": "device", "roles": "device role"}.get(route[0], route[0])
        return f"Add {what} {body.get('uid') or body.get('name') or body.get('machine') or ''}".strip()
    if route[0] == "domain":
        if route[1] == "grants":
            if len(route) == 2:
                return f"Add grant {body.get('name', '')}".strip()
            return f"{'Remove' if route[3:] == ['delete'] else 'Change'} grant {route[2]}"
        return {"password-policy": "Change the password policy", "kerberos": "Change the Kerberos ticket policy"}.get(
            route[1], "Change " + "/".join(route))
    if route[0] == "gpo":
        return f"{'Set' if route[1] == 'set' else 'Clear'} policy {body.get('policy', '')}".strip()
    if route[0] == "ous":
        return {"rename": f"Rename OU {body.get('ou', '')}", "delete": f"Remove OU {body.get('ou', '')}"}.get(
            route[1], "Change OUs")
    if route[0] in ("devices", "roles"):
        what = "device" if route[0] == "devices" else "device role"
        if route[2:] == ["delete"]:
            return f"Remove {what} {name}"
        if route[2:] == ["certs"]:
            return f"Unlink a certificate from device {name}"
        return f"Change {what} {name}"
    action = route[-1]
    if action == "groups":
        verb = "Add" if body.get("action") == "add" else "Remove"
        return f"{verb} {name} {'to' if verb == 'Add' else 'from'} group {body.get('group', '')}"
    if action == "members" and route[0] == "groups":
        verb = "Add" if body.get("action") == "add" else "Remove"
        return f"{verb} {body.get('member', '')} {'to' if verb == 'Add' else 'from'} group {name}"
    if action == "members" and route[0] == "host-groups":
        verb = "Add" if body.get("action") == "add" else "Remove"
        return f"{verb} {body.get('machine', '')} {'to' if verb == 'Add' else 'from'} machine group {name}"
    return f"{VERBS.get(action, action.capitalize())} {name}".strip()


def state_change(route, state):
    """Purpose: What an action with no fields changes, for the Review's Was and Becomes (manual 1.8.6.5): enabling or
             disabling a thing (a person's "enabled" is that they are not disabled or locked out), removing one.
    Inputs:  route — segments after /v1/; state — the thing's read (thing_state), or None.
    Returns: ({field: was}, {field: becomes}), both empty for another change.
    Fails:   never.
    Feeds:   agent/pending_store (the old and new values)."""
    action, row = (route[-1] if len(route) > 1 else ""), (state if isinstance(state, dict) else None)
    if action in ("enable", "disable"):
        was = {} if row is None else {"enabled": "yes" if row.get("enabled", not row.get("locked")) else "no"}
        return was, {"enabled": "yes" if action == "enable" else "no"}
    if action == "delete":
        return ({"exists": "yes"} if row is not None else {}), {"exists": "no (removed)"}
    return {}, {}


def own_state(kind, row):
    """Purpose: A device or device role as a change to it is read: its own fields, under "fields" as a save sends them
             (so the Review's Was sets them beside the Becomes), and a device's certificates.
    Inputs:  kind — "devices" or "roles"; row — the read's row, or None.
    Returns: {"fields": {...}, "certs": [...] (devices)}, or None for a row that is not there.
    Fails:   never.
    Feeds:   thing_state; the dev preview's pending store."""
    if row is None:
        return None
    state = {"fields": {k: row.get(k) for k in OWN_FIELDS[kind]}}
    if kind == "devices":
        state["certs"] = list(row.get("certs") or [])
    return state


def _find(rows, key, value):
    """Purpose: The row of a list whose key is a value.
    Inputs:  rows — list of dicts (or anything else: none found); key — str; value — str.
    Returns: the row, or None.
    Fails:   never.
    Feeds:   thing_state."""
    return next((r for r in rows or [] if isinstance(r, dict) and str(r.get(key)) == str(value)), None)


def thing_state(route, body, v):
    """Purpose: The agent's own read of the thing a change changes (decision 2.1.8.14): a person, a machine, a host
             group, a sudo rule, the password policy, the Group Policy set, a group, the OU tree, a grant.
    Inputs:  route — the change's segments after /v1/; body — its JSON body; v — vars (load_vars()).
    Returns: the thing as the read route returns it (a dict or list), or None when it does not exist yet (an add).
    Fails:   what the read raises (ValidationError: the directory cannot be read now).
    Feeds:   version_of; agent/pending_store (hold and apply)."""
    from fabriclib.directory.list_host_groups import list_host_groups
    from fabriclib.directory.list_machines import list_machines
    from fabriclib.directory.list_people import list_people
    from fabriclib.directory.list_sudo_rules import list_sudo_rules
    from fabriclib.domain.list_groups import list_groups
    from fabriclib.domain.list_ous import list_ous
    from fabriclib.domain.show_person import show_person
    from fabriclib.samba.gpo_overview import gpo_overview
    from fabriclib.samba.kerberos_overview import kerberos_overview
    from fabriclib.grants.list_grants import list_grants
    mine, route = as_change(route) is not route, as_change(route)
    head, name = route[0], (route[1] if len(route) > 1 else "")
    if mine:                                  # a member change from My account: the group must be there
        group = _find(list_groups(v).get("groups"), "name", name)
        if group is None:
            raise ValidationError(f"no group {name}")
        return group
    if head == "people":
        row = _find(list_people(v).get("users"), "uid", name if len(route) > 1 else body.get("uid", ""))
        return {**row, **show_person(v, row["uid"])["person"]} if row else None
    if head == "machines":                    # its machine groups are theirs: a member change is the group's
        row = _find(list_machines(v), "name", name if len(route) > 1 else body.get("name", ""))
        return {k: x for k, x in row.items() if k != "groups"} if row else None
    if head == "host-groups":
        short = name if len(route) > 1 else body.get("name", "")
        return _find(list_host_groups(v), "short", short) or _find(list_host_groups(v), "name", short)
    if head == "sudo":
        return _find(list_sudo_rules(v), "name", name if len(route) > 1 else body.get("name", ""))
    if route == ["domain", "password-policy"]:
        return v.get("ad_password_policy") or {}          # fabric's setting, written into the domain at Apply
    if route == ["domain", "kerberos", "policy"]:
        return kerberos_overview(v).get("policy")
    if route[:2] == ["domain", "grants"]:
        return _find(list_grants(v).get("grants"), "name", route[2] if len(route) > 2 else body.get("name", ""))
    if head == "gpo":
        gpo = gpo_overview(v)
        return {"settings": gpo.get("settings"), "controls": gpo.get("controls")}
    if head in ("devices", "roles"):           # its own fields (as a save sends them); a device's certificates
        from fabriclib.directory.device_overview import device_overview
        row = _find(device_overview(v).get(head), "name", name if len(route) > 1 else body.get("name", ""))
        return own_state(head, row)
    if head == "groups":
        return _find(list_groups(v).get("groups"), "name", name if len(route) > 1 else body.get("name", ""))
    if head == "ous":
        return list_ous(v)
    raise ValidationError("this change is not held: it is done at once")


def thing_key(route, body):
    """Purpose: Which thing a change changes, as a key: two changes of one apply on the same person, machine or
             policy share it (the second is not refused for the first one's change).
    Inputs:  route — segments after /v1/; body — the change's body.
    Returns: a tuple: (kind, name) — the name from the route, or from the body for an add; ("gpo",) and ("ous",)
             for the GPO's set and the OU tree; the route's first two segments for another thing with no name (a
             policy).
    Fails:   never.
    Feeds:   agent/pending_store (apply)."""
    route = as_change(route)
    if route[0] in ("people", "machines", "host-groups", "sudo", "groups", "devices", "roles"):
        return route[0], route[1] if len(route) > 1 else str(body.get("uid") or body.get("name") or "")
    if route[:2] == ["domain", "grants"]:
        return "grants", route[2] if len(route) > 2 else str(body.get("name") or "")
    if route[0] in ("gpo", "ous"):            # one thing each: the GPO's set, the OU tree (its creates, renames
        return (route[0],)                    # and deletes are read as the whole tree)
    return tuple(route[:2])


def version_of(state):
    """Purpose: A thing's version (decision 2.1.8.14): the SHA-256 of the agent's read of it.
    Inputs:  state — thing_state's answer (JSON-able, or None).
    Returns: 64 hex characters.
    Fails:   TypeError for a state that is not JSON-able.
    Feeds:   agent/pending_store."""
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()
