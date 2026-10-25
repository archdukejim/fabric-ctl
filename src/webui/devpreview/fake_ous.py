import re

from webui.devpreview.fabric_rules import ValidationError

ROOTS = ("people", "service-accounts", "groups", "machines/servers", "machines/desktops", "machines/network")
FIXED = ("people", "service-accounts", "groups", "groups/fabric", "machines", "machines/servers", "machines/desktops",
         "machines/network", "fabric-hosts", "devices", "device-roles", "networks", "sudoers")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$")
FABRIC_NAMES = {p.rpartition("/")[2].lower() for p in FIXED} | {"fabric"}
_EMPTY = {"people": 0, "groups": 0, "computers": 0, "ous": 0, "other": 0}
# what the preview's folders hold, by path; the rest hold nothing
SAMPLE_HOLDS = {"people": {"people": 3, "ous": 1}, "groups": {"groups": 6, "ous": 1},
                "machines": {"ous": 3}, "machines/servers": {"computers": 1, "ous": 1},
                "machines/desktops": {"computers": 1}, "people/staff": {"people": 1}}


def _tree(state):
    """Purpose: The preview's OU tree, kept in its state (changed by Apply).
    Inputs:  state — DevState.
    Returns: dict path -> {"fabric", "own", "holds"}.
    Fails:   never.
    Feeds:   fake_ous."""
    if "ous" not in state.data:
        paths = list(FIXED) + ["people/staff", "machines/servers/web"]
        state.data["ous"] = {p: {"fabric": p in FIXED, "own": p not in FIXED,
                                 "holds": {**_EMPTY, **SAMPLE_HOLDS.get(p, {})}} for p in paths}
    return state.data["ous"]


def _name(name):
    """Purpose: An OU name as the DC checks it.
    Inputs:  name — str.
    Returns: the name.
    Fails:   ValidationError for a bad name or one of fabric's folders' names.
    Feeds:   fake_ous."""
    if not NAME_RE.match(name):
        raise ValidationError("an OU's name: 1-63 letters, digits, space, _ . -, starting with a letter or digit")
    if name.lower() in FABRIC_NAMES:
        raise ValidationError(f"{name} is one of fabric's folders' names (manual 1.6.13.2): choose another")
    return name


def _own(tree, path):
    """Purpose: An admin's own OU, or why not.
    Inputs:  tree — _tree's dict; path — str.
    Returns: its entry.
    Fails:   ValidationError "no OU", or one of fabric's.
    Feeds:   fake_ous."""
    if path not in tree:
        raise ValidationError(f"no OU {path}")
    if not tree[path]["own"]:
        raise ValidationError(f"{path} is one of fabric's folders, or not below one an admin adds to: "
                              "managed by fabric")
    return tree[path]


def fake_ous(state, who, route, body):
    """Purpose: The fake agent's OUs (manual 1.6.12.7): GET /v1/ous; POST /v1/ous, /v1/ous/rename, /v1/ous/delete —
             in memory, refused as the DC refuses.
    Inputs:  state — DevState; who — {"user", "perms"}; route — segments after /v1/; body — dict, or None for a read.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the DC's reasons.
    Feeds:   fake_agent."""
    if route[:1] != ["ous"]:
        return None
    tree = _tree(state)
    if body is None:
        if route != ["ous"]:
            return None
        return {"ous": [{"path": p, "dn": "", **dict(e, holds=dict(e["holds"]))}
                        for p, e in sorted(tree.items(), key=lambda x: x[0].lower())]}
    if route == ["ous"]:
        parent, name = str(body.get("parent") or ""), _name(str(body.get("name") or ""))
        if parent not in tree:
            raise ValidationError(f"no OU {parent}")
        if parent not in ROOTS and not tree[parent]["own"]:
            raise ValidationError(f"{parent} takes no admin's folders: add them under {', '.join(ROOTS)}")
        path = f"{parent}/{name}"
        if path in tree:
            raise ValidationError(f"an OU {name} is already in {parent}")
        tree[path] = {"fabric": False, "own": True, "holds": dict(_EMPTY)}
        tree[parent]["holds"]["ous"] += 1
        return {"path": path, "dn": ""}
    path = str(body.get("ou") or "")
    entry = _own(tree, path)
    if route == ["ous", "delete"]:
        if any(entry["holds"].values()):
            raise ValidationError(f"{path} is not empty: it holds {sum(entry['holds'].values())} things "
                                  "(manual 1.6.12.7)")
        del tree[path]
        tree[path.rpartition("/")[0]]["holds"]["ous"] -= 1
        return {"path": path}
    if route == ["ous", "rename"]:
        new = f"{path.rpartition('/')[0]}/{_name(str(body.get('name') or ''))}"
        if new in tree and new != path:
            raise ValidationError(f"an OU {new.rpartition('/')[2]} is already beside {path}")
        for p in [p for p in tree if p == path or p.startswith(path + "/")]:
            tree[new + p[len(path):]] = tree.pop(p)
        return {"path": new, "dn": ""}
    return None
