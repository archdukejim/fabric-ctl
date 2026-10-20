import ldb

from open_samdb import open_samdb

# syntaxes: (attributeSyntax, oMSyntax)
STRING, BOOL, INT, IA5, TIME = ("2.5.5.12", 64), ("2.5.5.8", 1), ("2.5.5.9", 2), ("2.5.5.5", 22), ("2.5.5.11", 24)
# fabric's UUID (its 389-DS schema's arc 2.25.<UUID>); AD refuses an OID component above 32 bits, so it goes under
# Microsoft's arc for extensions without a registered number, split as Microsoft's generator splits a GUID (Q3)
UUID = 204492767351757179914238406906488345409
_H = f"{UUID:032x}"
FABRIC_ARC = "1.2.840.113556.1.8000.2554." + ".".join(
    str(int(_H[a:b], 16)) for a, b in ((0, 4), (4, 8), (8, 12), (12, 16), (16, 20), (20, 26), (26, 32)))
# (attribute arc, class arc, [(name, n, syntax, single)], [(name, n, category 1 structural / 3 auxiliary, must, may)])
SETS = {
    "fabric": (FABRIC_ARC + ".1", FABRIC_ARC + ".2",
               [("fabricDeviceType", 1, STRING, True), ("fabricEnabled", 2, BOOL, True),
                ("fabricCertFingerprint", 3, IA5, False), ("fabricPermission", 4, STRING, False),
                ("fabricVlan", 5, INT, True), ("fabricPriority", 6, INT, True), ("fabricRoleName", 7, STRING, False),
                ("fabricSite", 8, STRING, True), ("fabricCidr", 9, IA5, True), ("fabricNetworkKind", 10, STRING, True),
                ("fabricAllowOverlap", 11, STRING, True),
                # a DC's id range "first-last" (2.1.6.63); fabricIdNext is 0.6's high-water mark, no longer written
                ("fabricIdRange", 12, IA5, True), ("fabricIdNext", 13, INT, True),
                # a laid-out block's high-water mark per range, "<kind>=<next>" (2.1.6.46, manual 1.6.3.17)
                ("fabricIdMark", 14, IA5, False)],
               [("fabricDevice", 1, 3, [], ["fabricDeviceType", "fabricEnabled", "fabricCertFingerprint"]),
                ("fabricRole", 2, 3, [], ["fabricPermission", "fabricVlan", "fabricPriority"]),
                ("fabricDeviceRoles", 3, 3, [], ["fabricRoleName"]),
                ("fabricNetwork", 4, 1, ["fabricCidr"], ["fabricSite", "fabricVlan", "fabricNetworkKind",
                                                         "fabricAllowOverlap", "description"]),
                ("fabricSiteInfo", 5, 3, [], ["fabricIdRange", "fabricIdNext"]),
                ("fabricIdLayout", 6, 3, [], ["fabricIdMark"]),
                # a DC's record in CN=dcs,CN=fabric,CN=System: its site (2.1.6.79, manual 1.6.13.2)
                ("fabricDcInfo", 7, 3, [], ["fabricSite"])]),
    # sudo's rules in the directory, with sudo's own registered arc (Ubuntu no longer ships its AD schema; Q9)
    "sudo": ("1.3.6.1.4.1.15953.9.1", "1.3.6.1.4.1.15953.9.2",
             [("sudoUser", 1, IA5, False), ("sudoHost", 2, IA5, False), ("sudoCommand", 3, IA5, False),
              ("sudoRunAs", 4, IA5, False), ("sudoOption", 5, IA5, False), ("sudoRunAsUser", 6, IA5, False),
              ("sudoRunAsGroup", 7, IA5, False), ("sudoNotBefore", 8, TIME, False), ("sudoNotAfter", 9, TIME, False),
              ("sudoOrder", 10, INT, True)],
             [("sudoRole", 1, 1, ["cn"], ["sudoUser", "sudoHost", "sudoCommand", "sudoRunAs", "sudoRunAsUser",
                                          "sudoRunAsGroup", "sudoOption", "sudoNotBefore", "sudoNotAfter",
                                          "sudoOrder", "description"])]),
}
# a structural class's objects readable by authenticated users (machines included), or only admins see them (Q9)
DEFAULT_SD = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"


def _cn(name):
    """Purpose: a schema object's common name in AD's style: fabricDeviceType -> FabricDevice-Type.
    Inputs:  name — str, the lDAPDisplayName.
    Returns: str.
    Fails:   never.
    Feeds:   ensure_schema."""
    out = "".join(f"-{c}" if c.isupper() else c for c in name)
    return out[0].upper() + out[1:]


def _present(samdb, schema_dn):
    """Purpose: the lDAPDisplayNames already in the schema.
    Inputs:  samdb — SamDB; schema_dn — str.
    Returns: set of str.
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_schema."""
    return {str(m["lDAPDisplayName"]) for m in samdb.search(base=schema_dn, scope=ldb.SCOPE_ONELEVEL,
                                                             attrs=["lDAPDisplayName"]) if "lDAPDisplayName" in m}


def ensure_schema(conf):
    """Purpose: fabric's and sudo's attributes and classes in AD's schema (manual 1.6.3.5), each added once and never
             changed afterwards (a schema extension is permanent: a new need is a new OID).
    Inputs:  conf — str, the DC's smb.conf.
    Returns: list of str, the lDAPDisplayNames added (empty when the schema already has them).
    Fails:   ldb.LdbError from an addition the schema refuses (nothing after it is added).
    Feeds:   converge.
    Notes:   two sessions, as Q3 proved necessary: the attributes, a schema reload, then (with a fresh connection)
             the classes that use them."""
    added = []
    for part in ("attributes", "classes"):
        samdb, _ = open_samdb(conf, schema_updates=True)
        schema_dn = str(samdb.get_schema_basedn())
        have = _present(samdb, schema_dn)
        for attr_arc, class_arc, attrs, classes in SETS.values():
            if part == "attributes":
                for name, n, (syntax, om), single in attrs:
                    if name in have:
                        continue
                    samdb.add({"dn": f"CN={_cn(name)},{schema_dn}", "objectClass": ["top", "attributeSchema"],
                               "attributeID": f"{attr_arc}.{n}", "lDAPDisplayName": name, "adminDisplayName": _cn(name),
                               "attributeSyntax": syntax, "oMSyntax": str(om),
                               "isSingleValued": "TRUE" if single else "FALSE", "searchFlags": "1"})
                    added.append(name)
                continue
            for name, n, category, must, may in classes:
                if name in have:
                    continue
                msg = {"dn": f"CN={_cn(name)},{schema_dn}", "objectClass": ["top", "classSchema"],
                       "governsID": f"{class_arc}.{n}", "lDAPDisplayName": name, "adminDisplayName": _cn(name),
                       "subClassOf": "top", "objectClassCategory": str(category),
                       "defaultObjectCategory": f"CN={_cn(name)},{schema_dn}"}
                if must:
                    msg["mustContain"] = must
                if may:
                    msg["mayContain"] = may
                if category == 1:
                    msg["possSuperiors"] = ["organizationalUnit", "container"]
                    msg["defaultSecurityDescriptor"] = DEFAULT_SD
                samdb.add(msg)
                added.append(name)
        if added:
            samdb.modify_ldif("dn:\nchangetype: modify\nadd: schemaUpdateNow\nschemaUpdateNow: 1\n")
    return added
