"""The local-admin switches kept in the domain (manual 1.7.1.4.6, decision 2.1.7.19): one object per target under
`CN=local-admin,CN=fabric,CN=System`, of AD's own class for an application's settings with the JSON in
`msDS-Settings`, as the grants are (2.3.6.19.3). 0.8.0 knows one kind of target, the host that runs a DC
(`CN=dc-host-<dc>`); 0.10.0 adds machine groups to the same store. No object: the switch is off. The Enterprise
Admin's acknowledgement of a switch's alert (2.1.7.21) is kept with it until the switch next changes."""
import json

import ldb

import paths

CLASS = "msDS-App-Configuration"
ATTR = "msDS-Settings"


def store_dn(samdb):
    """Purpose: the container of the local-admin switches.
    Inputs:  samdb — SamDB.
    Returns: str "CN=local-admin,CN=fabric,CN=System,<domain>".
    Fails:   never.
    Feeds:   read_switch, write_switch."""
    return f"CN=local-admin,{paths.fabric_dn(samdb)}"


def _cn(dc):
    """Purpose: the object's name for the host that runs a DC.
    Inputs:  dc — the DC's name (dc-NNNN).
    Returns: str "dc-host-<dc>".
    Fails:   never.
    Feeds:   read_switch, write_switch."""
    return f"dc-host-{dc.lower()}"


def read_switch(samdb, dc):
    """Purpose: the switch of the host that runs a DC.
    Inputs:  samdb — SamDB; dc — the DC's name.
    Returns: {"dc", "ssh": bool, "by", "when", "ack"}: off, by, when and ack None, when nothing is stored; "ack" is
             {"by", "when"} once the Enterprise Admin acknowledged the alert of the switch as it is (2.1.7.21), else
             None.
    Fails:   ldb.LdbError other than a missing object or store; ValueError for a value that is not JSON.
    Feeds:   local_admin_tool (get, set, ack); write_switch, ack_switch."""
    try:
        res = samdb.search(base=f"CN={_cn(dc)},{store_dn(samdb)}", scope=ldb.SCOPE_BASE, attrs=[ATTR])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return {"dc": dc.lower(), "ssh": False, "by": None, "when": None, "ack": None}
        raise
    stored = json.loads(str(res[0][ATTR][0])) if res and res[0].get(ATTR) else {}
    ack = stored.get("ack") if isinstance(stored.get("ack"), dict) else None
    return {"dc": dc.lower(), "ssh": stored.get("ssh") is True, "by": stored.get("by"), "when": stored.get("when"),
            "ack": ack}


def write_switch(samdb, dc, ssh, by, when):
    """Purpose: the switch of the host that runs a DC stored (the store made when missing); nothing written when it
             already holds that value.
    Inputs:  samdb — SamDB (as the system, at a writable DC); dc — the DC's name; ssh — bool; by, when — who set it
             and when (str).
    Returns: bool, whether it changed.
    Fails:   ldb.LdbError from AD.
    Feeds:   local_admin_tool (set)."""
    if read_switch(samdb, dc)["ssh"] is ssh:
        return False
    try:
        samdb.add({"dn": store_dn(samdb), "objectClass": "container"})
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
    text = json.dumps({"kind": "dc-host", "dc": dc.lower(), "ssh": ssh, "by": by, "when": when}, sort_keys=True)
    dn = f"CN={_cn(dc)},{store_dn(samdb)}"
    try:
        samdb.add({"dn": dn, "objectClass": CLASS, ATTR: text})
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
        _replace(samdb, dn, text)
    return True


def _replace(samdb, dn, text):
    """Purpose: an existing switch object's JSON replaced.
    Inputs:  samdb — SamDB; dn — the object's DN; text — the JSON.
    Returns: None.
    Fails:   ldb.LdbError from AD.
    Feeds:   write_switch, ack_switch."""
    msg = ldb.Message(ldb.Dn(samdb, dn))
    msg[ATTR] = ldb.MessageElement([text], ldb.FLAG_MOD_REPLACE, ATTR)
    samdb.modify(msg)


def ack_switch(samdb, dc, by, when):
    """Purpose: the alert of a switch that is on acknowledged by the Enterprise Admin (decision 2.1.7.21): who and when
             kept with the switch, until the switch next changes; nothing written when it is already acknowledged.
    Inputs:  samdb — SamDB (as the system, at a writable DC); dc — the DC's name; by, when — who acknowledged it and
             when (str).
    Returns: bool, whether it changed.
    Fails:   ValueError while the switch is off (no alert to acknowledge); ldb.LdbError from AD.
    Feeds:   local_admin_tool (ack)."""
    now = read_switch(samdb, dc)
    if not now["ssh"]:
        raise ValueError(f"local-admin over SSH is off for {dc.lower()}'s host: there is no alert to acknowledge")
    if now["ack"]:
        return False
    text = json.dumps({"kind": "dc-host", "dc": dc.lower(), "ssh": True, "by": now["by"], "when": now["when"],
                       "ack": {"by": by, "when": when}}, sort_keys=True)
    _replace(samdb, f"CN={_cn(dc)},{store_dn(samdb)}", text)
    return True
