import ldb

import paths


def _owner_dn(samdb, owner):
    """Purpose: a device owner's DN, by their user name.
    Inputs:  samdb — SamDB; owner — user name.
    Returns: str.
    Fails:   ValueError "no such user: <owner>".
    Feeds:   save_device."""
    found = samdb.search(base=paths.folder_dn(samdb, "people"), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectCategory=person)(sAMAccountName={ldb.binary_encode(owner)}))",
                         attrs=["dn"])
    if not found:
        raise ValueError(f"no such user: {owner}")
    return str(found[0].dn)


def save_device(samdb, lp, site, name, type, macs, owner, description, enabled, roles, new):
    """Purpose: a device in the domain's OU=devices (manual 1.6.13.2): added, or its type, MACs, owner, description,
             enabled flag and roles replaced. Fields are checked by fabric first (check_device_fields).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the device's name;
             type, description — str; macs — list of normalised MACs; owner — user name or ""; enabled — bool;
             roles — list of role names (on the device, fabricRoleName); new — bool: add (else replace).
    Returns: {"name"}.
    Fails:   ValueError "no such user: <owner>"; ldb.LdbError ERR_ENTRY_ALREADY_EXISTS (add), ERR_NO_SUCH_OBJECT
             (replace), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (ops "add_device", "update_device")."""
    dn = f"CN={name},{paths.folder_dn(samdb, 'devices')}"
    values = {"fabricDeviceType": type, "fabricEnabled": "TRUE" if enabled else "FALSE", "macAddress": macs,
              "description": description, "owner": _owner_dn(samdb, owner) if owner else "",
              "fabricRoleName": roles}
    if new:
        msg = {"dn": dn, "objectClass": ["device", "ieee802Device", "fabricDevice", "fabricDeviceRoles"]}
        msg.update({k: val for k, val in values.items() if val})
        samdb.add(msg)
        return {"name": name}
    msg = ldb.Message(ldb.Dn(samdb, dn))
    for k, val in values.items():
        msg[k] = ldb.MessageElement(val if isinstance(val, list) else ([val] if val else []), ldb.FLAG_MOD_REPLACE, k)
    samdb.modify(msg)
    return {"name": name}
