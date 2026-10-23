"""The grant store (manual 1.6.13.4, 2.1.6.79): one object per grant under `CN=grants,CN=fabric,CN=System`, its
definition JSON in the object's `msDS-Settings`, and the compiler's record of the sets of machines beside them
(`CN=_compiled`). An object of AD's own class for an application's settings, `msDS-App-Configuration`, because AD
refuses `info` on a `container` (2.3.6.19.3); no schema extension. Every DC holds it; only fabric writes it."""
import json

import ldb

from grant_names import FIELDS, STATE
import paths

CLASS = "msDS-App-Configuration"
ATTR = "msDS-Settings"


def store_dn(samdb):
    """Purpose: the container that holds the grants.
    Inputs:  samdb — SamDB.
    Returns: str "CN=grants,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   ensure_layout, the store's functions below."""
    return f"CN=grants,{paths.fabric_dn(samdb)}"


def _read(samdb, cn):
    """Purpose: one stored record's JSON.
    Inputs:  samdb — SamDB; cn — the object's name.
    Returns: dict, or None when there is no such object.
    Fails:   ldb.LdbError other than "no such object"; ValueError for a value that is not JSON.
    Feeds:   read_grant, read_state."""
    try:
        res = samdb.search(base=f"CN={ldb.binary_encode(cn)},{store_dn(samdb)}", scope=ldb.SCOPE_BASE, attrs=[ATTR])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    return json.loads(str(res[0][ATTR][0])) if res and res[0].get(ATTR) else {}


def _write(samdb, cn, value):
    """Purpose: one record written, created when missing; nothing written when it already holds that value.
    Inputs:  samdb — SamDB (as the system); cn — str; value — JSON-able dict.
    Returns: bool, whether it changed.
    Fails:   ldb.LdbError from AD.
    Feeds:   write_grant, write_state."""
    text = json.dumps(value, sort_keys=True)
    have = _read(samdb, cn)
    dn = f"CN={cn},{store_dn(samdb)}"
    if have is None:
        samdb.add({"dn": dn, "objectClass": CLASS, ATTR: text})
        return True
    if json.dumps(have, sort_keys=True) == text:
        return False
    msg = ldb.Message(ldb.Dn(samdb, dn))
    msg[ATTR] = ldb.MessageElement([text], ldb.FLAG_MOD_REPLACE, ATTR)
    samdb.modify(msg)
    return True


def read_grants(samdb):
    """Purpose: every stored grant, each with all of FIELDS (an older record's missing field as empty).
    Inputs:  samdb — SamDB.
    Returns: list of dict (name and FIELDS' keys), by name; [] before the store exists.
    Fails:   ldb.LdbError other than a missing store; ValueError for a record that is not JSON.
    Feeds:   compile_grants, explain_grants, grants_tool (list), ship_grants."""
    try:
        res = samdb.search(base=store_dn(samdb), scope=ldb.SCOPE_ONELEVEL, expression=f"(objectClass={CLASS})",
                           attrs=["cn", ATTR])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return []
        raise
    out = []
    for m in res:
        name = str(m["cn"][0])
        if name == STATE:
            continue
        stored = json.loads(str(m[ATTR][0])) if m.get(ATTR) else {}
        out.append({**FIELDS, **stored, "name": name})
    return sorted(out, key=lambda g: g["name"])


def read_grant(samdb, name):
    """Purpose: one stored grant.
    Inputs:  samdb — SamDB; name — str.
    Returns: dict (name and FIELDS' keys), or None.
    Fails:   as _read.
    Feeds:   grants_tool (show, set, remove)."""
    if name == STATE:
        return None
    stored = _read(samdb, name)
    return None if stored is None else {**FIELDS, **stored, "name": name}


def write_grant(samdb, grant):
    """Purpose: a grant stored as given (its name is the object's).
    Inputs:  samdb — SamDB (as the system); grant — dict with name and FIELDS' keys, already checked (check_grant).
    Returns: bool, whether it changed.
    Fails:   ldb.LdbError from AD (the store missing: the domain has not converged).
    Feeds:   grants_tool (add, set), ship_grants."""
    return _write(samdb, grant["name"], {k: grant[k] for k in FIELDS})


def delete_grant(samdb, name):
    """Purpose: a grant removed from the store.
    Inputs:  samdb — SamDB (as the system); name — str.
    Returns: None.
    Fails:   ValueError "no grant <name>"; ldb.LdbError from AD.
    Feeds:   grants_tool (remove)."""
    if read_grant(samdb, name) is None:
        raise ValueError(f"no grant {name}")
    samdb.delete(f"CN={name},{store_dn(samdb)}")


def read_state(samdb):
    """Purpose: the compiler's record: the sets of machines by number, the next number, whether the shipped grants
             were made.
    Inputs:  samdb — SamDB.
    Returns: dict {"next": int, "sets": {"<n>": {"allow": [names], "restrict": [names]}}, "shipped": bool,
             "shipped_networks": bool (0.9.0's network-plan made, 1.6.13.12)}.
    Fails:   as _read.
    Feeds:   compile_grants, ship_grants, show_grant."""
    return {"next": 1, "sets": {}, "shipped": False, "shipped_networks": False, **(_read(samdb, STATE) or {})}


def write_state(samdb, state):
    """Purpose: the compiler's record written.
    Inputs:  samdb — SamDB (as the system); state — read_state's shape.
    Returns: bool, whether it changed.
    Fails:   ldb.LdbError from AD.
    Feeds:   compile_grants, ship_grants."""
    return _write(samdb, STATE, state)
