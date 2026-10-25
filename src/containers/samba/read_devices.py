import ldb

import paths


def _one(m, name, default=""):
    """Purpose: an entry's first value of an attribute, as text.
    Inputs:  m — ldb.Message; name — attribute; default — when absent.
    Returns: str.
    Fails:   never.
    Feeds:   read_devices."""
    return str(m[name][0]) if name in m else default


def read_devices(samdb, lp, site):
    """Purpose: the domain's devices (OU=devices) and its device roles (OU=device-roles), raw, in one read (manual
             1.6.13.2, 2.1.6.80; the data shapes fabric's device code and the web UI use).
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: devices and roles are the
             domain's).
    Returns: {"devices": [{name, type, enabled, macs, owner (DN or ""), description, certs (SHA-256 fingerprints),
             roles (the role names the device carries)}], "roles": [{name, description, permissions, vlan (int or
             None), priority (int, default 100), members (device names, from the devices' roles), dn}]}.
    Fails:   ldb.LdbError from a search.
    Feeds:   directory_ops (op "read_devices")."""
    devices = []
    for m in samdb.search(base=paths.folder_dn(samdb, "devices"), scope=ldb.SCOPE_ONELEVEL,
                          expression="(objectClass=device)",
                          attrs=["cn", "fabricDeviceType", "fabricEnabled", "macAddress", "owner", "description",
                                 "fabricCertFingerprint", "fabricRoleName"]):
        devices.append({"name": _one(m, "cn"), "type": _one(m, "fabricDeviceType", "other"),
                        "enabled": _one(m, "fabricEnabled", "TRUE").upper() == "TRUE",
                        "macs": [str(x) for x in m.get("macAddress", [])], "owner": _one(m, "owner"),
                        "description": _one(m, "description"),
                        "certs": [str(x) for x in m.get("fabricCertFingerprint", [])],
                        "roles": sorted(str(x) for x in m.get("fabricRoleName", []))})
    roles = []
    for m in samdb.search(base=paths.folder_dn(samdb, "device-roles"), scope=ldb.SCOPE_SUBTREE,
                          expression="(&(objectClass=group)(objectClass=fabricRole))",
                          attrs=["cn", "description", "fabricPermission", "fabricVlan", "fabricPriority"]):
        roles.append({"name": _one(m, "cn"), "description": _one(m, "description"),
                      "permissions": [str(x) for x in m.get("fabricPermission", [])],
                      "vlan": int(_one(m, "fabricVlan", "0")) or None,
                      "priority": int(_one(m, "fabricPriority", "100")), "dn": str(m.dn)})
    for r in roles:                      # a device names its roles (fabricRoleName); a role lists no members
        r["members"] = sorted(d["name"] for d in devices if r["name"].lower() in {x.lower() for x in d["roles"]})
    return {"devices": devices, "roles": roles}
