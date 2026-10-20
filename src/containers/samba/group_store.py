"""A group's managers and what they may do (manual 1.6.12.5, 2.1.6.67): level 1 of the group, kept in fabric's state
(2.1.6.79) as one object per managed group under `CN=groups,CN=fabric,CN=System`, named by the group's objectGUID (so
a rename keeps it), of AD's own class for an application's settings with the JSON in `msDS-Settings` (as the grants
are, 2.3.6.19.3). The Directory Administrators have no rights on `CN=fabric,CN=System`, so no manager can widen their
own controls with other tools. The group's `managedBy` names the first manager for tools that read it."""
import json

import ldb

import paths

CLASS = "msDS-App-Configuration"
ATTR = "msDS-Settings"
EMPTY = {"managers": [], "add": False, "remove": False, "only_from": ""}


def store_dn(samdb):
    """Purpose: the container of the groups' managers.
    Inputs:  samdb — SamDB.
    Returns: str "CN=groups,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   read_managers, write_managers."""
    return f"CN=groups,{paths.fabric_dn(samdb)}"


def group_guid(samdb, group_dn):
    """Purpose: a group's objectGUID as text, the name its managers' record takes.
    Inputs:  samdb — SamDB; group_dn — str.
    Returns: str.
    Fails:   ldb.LdbError for no such group.
    Feeds:   read_managers, write_managers."""
    res = samdb.search(base=group_dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
    return str(samdb.schema_format_value("objectGUID", res[0]["objectGUID"][0]), "utf-8")


def read_managers(samdb, group_dn):
    """Purpose: a group's managers and their controls.
    Inputs:  samdb — SamDB; group_dn — the group's DN.
    Returns: {"managers": [names], "add": bool, "remove": bool, "only_from": group name or ""} (EMPTY when none set,
             or before the container exists).
    Fails:   ldb.LdbError other than "no such object"; ValueError for a record that is not JSON.
    Feeds:   authorize_action, group_scope, set_group_managers, remove_group."""
    guid = group_guid(samdb, group_dn)
    try:
        res = samdb.search(base=f"CN={guid},{store_dn(samdb)}", scope=ldb.SCOPE_BASE, attrs=[ATTR])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return dict(EMPTY)
        raise
    stored = json.loads(str(res[0][ATTR][0])) if res and res[0].get(ATTR) else {}
    return {**EMPTY, **stored}


def all_managers(samdb):
    """Purpose: every group's managers' record, for the checks that a group is still named by one (delete).
    Inputs:  samdb — SamDB.
    Returns: list of the stored dicts (EMPTY's keys); [] before the container exists.
    Fails:   ldb.LdbError other than a missing container; ValueError for a record that is not JSON.
    Feeds:   group_uses."""
    try:
        res = samdb.search(base=store_dn(samdb), scope=ldb.SCOPE_ONELEVEL, expression=f"(objectClass={CLASS})",
                           attrs=[ATTR, "cn"])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return []
        raise
    return [{**EMPTY, **json.loads(str(m[ATTR][0])), "guid": str(m["cn"][0])} for m in res if m.get(ATTR)]


def write_managers(samdb, group_dn, record, first_dn):
    """Purpose: a group's managers stored (the record removed when it names no manager), and its `managedBy` set to the
                 first manager (or cleared).
    Inputs:  samdb — SamDB (as fabric's agent account, which has full control of CN=fabric); group_dn — str; record —
             EMPTY's shape, already checked; first_dn — the first manager's DN, or None.
    Returns: bool, whether anything changed.
    Fails:   ldb.LdbError from AD (the container missing: the domain has not converged, ensure_layout).
    Feeds:   set_group_managers."""
    guid, changed = group_guid(samdb, group_dn), False
    have = read_managers(samdb, group_dn)
    dn = f"CN={guid},{store_dn(samdb)}"
    text = json.dumps({k: record[k] for k in EMPTY}, sort_keys=True)
    if not record["managers"]:
        if have != EMPTY:
            samdb.delete(dn)
            changed = True
    elif have == EMPTY:
        samdb.add({"dn": dn, "objectClass": CLASS, ATTR: text})
        changed = True
    elif json.dumps(have, sort_keys=True) != text:
        msg = ldb.Message(ldb.Dn(samdb, dn))
        msg[ATTR] = ldb.MessageElement([text], ldb.FLAG_MOD_REPLACE, ATTR)
        samdb.modify(msg)
        changed = True
    cur = samdb.search(base=group_dn, scope=ldb.SCOPE_BASE, attrs=["managedBy"])[0].get("managedBy")
    cur = str(cur[0]) if cur else None
    if (cur or "").lower() != (first_dn or "").lower():
        msg = ldb.Message(ldb.Dn(samdb, group_dn))
        msg["managedBy"] = (ldb.MessageElement([first_dn], ldb.FLAG_MOD_REPLACE, "managedBy") if first_dn
                            else ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "managedBy"))
        samdb.modify(msg)
        changed = True
    return changed


def drop_managers(samdb, group_dn):
    """Purpose: a deleted group's managers' record removed with it.
    Inputs:  samdb — SamDB (as fabric's agent account); group_dn — str (the group still exists).
    Returns: None.
    Fails:   ldb.LdbError from AD other than "no such object".
    Feeds:   remove_group."""
    try:
        samdb.delete(f"CN={group_guid(samdb, group_dn)},{store_dn(samdb)}")
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
