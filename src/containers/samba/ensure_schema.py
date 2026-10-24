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
# (attribute arc, class arc, [(name, n, syntax, single)], [(name, n, category 1 structural / 3 auxiliary, must, may
# [, possible superiors: a structural class's default is an OU or a container])])
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
                ("fabricIdMark", 14, IA5, False),
                # the address manager's plan (manual 1.10.4.13.1, 1.10.4.31): VLANs, subnets, ranges, addresses, a
                # site's number (on its record, 2.1.10.34)
                ("fabricPurpose", 15, STRING, True), ("fabricAccess", 16, STRING, True),
                ("fabricGateway", 17, IA5, True), ("fabricDhcpServed", 18, BOOL, True),
                ("fabricSubnetId", 19, INT, True), ("fabricRelay", 20, IA5, True),
                ("fabricDhcpOption", 21, STRING, False), ("fabricRangeKind", 22, STRING, True),
                ("fabricFirst", 23, IA5, True), ("fabricLast", 24, IA5, True), ("fabricIp", 25, IA5, True),
                ("fabricAddressKind", 26, STRING, True), ("fabricMac", 27, IA5, True),
                ("fabricHostName", 28, IA5, True), ("fabricOwner", 29, STRING, True), ("fabricDns", 30, BOOL, True),
                ("fabricBlock", 31, INT, True), ("fabricVlanName", 32, STRING, True),
                # the option sets: the domain's and each site's (2.1.10.23, 2.1.10.34; manual 1.10.4.24.1)
                ("fabricDhcpOptionDef", 33, STRING, False), ("fabricDhcpClass", 34, STRING, False),
                # a scan requested at the site that serves the subnet, and its answer (2.1.10.38, manual 1.10.4.36)
                ("fabricScanRequestedBy", 41, STRING, True), ("fabricScanActor", 42, STRING, True),
                ("fabricScanState", 43, STRING, True), ("fabricScanResult", 44, STRING, True),
                ("fabricScanDoneAt", 45, IA5, True)],
               [("fabricDevice", 1, 3, [], ["fabricDeviceType", "fabricEnabled", "fabricCertFingerprint"]),
                ("fabricRole", 2, 3, [], ["fabricPermission", "fabricVlan", "fabricPriority"]),
                ("fabricDeviceRoles", 3, 3, [], ["fabricRoleName"]),
                ("fabricNetwork", 4, 1, ["fabricCidr"], ["fabricSite", "fabricVlan", "fabricNetworkKind",
                                                         "fabricAllowOverlap", "description"]),
                ("fabricSiteInfo", 5, 3, [], ["fabricIdRange", "fabricIdNext"]),
                ("fabricIdLayout", 6, 3, [], ["fabricIdMark"]),
                # a DC's record in CN=dcs,CN=fabric,CN=System: its site (2.1.6.79, manual 1.6.13.2)
                ("fabricDcInfo", 7, 3, [], ["fabricSite"]),
                # the address manager (manual 1.10.4.31): a subnet's own fields on its fabricNetwork entry; a range,
                # an address and a scan request, each below its subnet's entry
                ("fabricSubnet", 8, 3, [], ["fabricGateway", "fabricDhcpServed", "fabricSubnetId", "fabricRelay",
                                            "fabricDhcpOption"]),
                ("fabricRange", 9, 1, ["fabricRangeKind", "fabricFirst", "fabricLast"], ["description"],
                 ["fabricNetwork"]),
                ("fabricAddress", 10, 1, ["fabricIp", "fabricAddressKind"],
                 ["fabricMac", "fabricHostName", "fabricOwner", "fabricDns", "fabricDhcpOption", "description"],
                 ["fabricNetwork"]),
                # the domain's DHCP options (CN=dhcp-options,CN=fabric,CN=System, 2.1.10.34)
                ("fabricOptionSet", 12, 1, [], ["fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass",
                                                "description"]),
                ("fabricScanRequest", 16, 1, ["fabricCidr", "fabricScanRequestedBy"],
                 ["fabricScanActor", "fabricScanState", "fabricScanResult", "fabricScanDoneAt", "description"],
                 ["fabricNetwork"]),
                # a VLAN, in OU=networks (17: 7 is fabricDcInfo, 2.1.10.33)
                ("fabricVlanRecord", 17, 1, ["fabricVlan", "fabricVlanName"],
                 ["fabricSite", "fabricPurpose", "fabricAccess", "description"]),
                # a site's record, CN=<site>,CN=sites,CN=fabric,CN=System: its number and its options (2.1.10.34)
                ("fabricSiteRecord", 18, 1, [], ["fabricBlock", "fabricDhcpOption", "fabricDhcpOptionDef",
                                                 "fabricDhcpClass", "description"], ["container"])]),
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
# numbers once given on a pre-release branch and dropped: never given again (2.1.10.33; a schema OID is permanent,
# and a lab domain may hold one). tests/samba/ensure_schema_test.py refuses a live entry on one.
RETIRED = {
    # fabricScanPolicy 35, fabricScanEnforced 36, class fabricScanPolicySet 13 (2.1.10.28, dropped by 2.1.10.30);
    # fabricLocalScan 39, fabricLocalScanBy 40, class fabricLocalScanSet 15 (2.1.10.30, dropped by 2.1.10.38);
    # class fabricAddressBlock 11 (a site OU's number: on the site's record since 2.1.10.34)
    "fabric": {"attributes": {35, 36, 39, 40}, "classes": {11, 13, 15}},
}
# numbers held for another release's branch, not given here (2.1.10.33): the SSH host's on dev/0.10.0-8021x
# (37, 38, class 14); the site tree's on dev/0.8.0-console (fabricParentSite 46, fabricConsoleUrl 47, class
# fabricSiteTree 19, auxiliary: given there, so ensure_schema agrees when 0.8.0 merges in)
RESERVED = {"fabric": {"attributes": {37, 38, 46, 47}, "classes": {14, 19}}}
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
    """Purpose: the schema's attributes and classes, each with its OID.
    Inputs:  samdb — SamDB; schema_dn — str.
    Returns: dict lDAPDisplayName -> OID str (its attributeID or governsID).
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_schema."""
    out = {}
    for m in samdb.search(base=schema_dn, scope=ldb.SCOPE_ONELEVEL,
                          attrs=["lDAPDisplayName", "attributeID", "governsID"]):
        if "lDAPDisplayName" in m:
            oid = m.get("attributeID", idx=0) or m.get("governsID", idx=0)
            out[str(m["lDAPDisplayName"])] = str(oid or "")
    return out


def wanted_oids(sets=None):
    """Purpose: every name of fabric's and sudo's schema with the OID it must have.
    Inputs:  sets — SETS' shape (default SETS).
    Returns: dict name -> OID str.
    Fails:   never.
    Feeds:   schema_problems."""
    out = {}
    for attr_arc, class_arc, attrs, classes in (sets or SETS).values():
        out.update({a[0]: f"{attr_arc}.{a[1]}" for a in attrs})
        out.update({c[0]: f"{class_arc}.{c[1]}" for c in classes})
    return out


def schema_problems(present, sets=None):
    """Purpose: how a domain's schema disagrees with fabric's (2.1.10.33, manual 1.10.4.31): one of fabric's names
             under another OID, or one of fabric's OIDs under another name (a lab domain that ran a pre-release
             build, where class 7 was the VLAN record). A name fabric does not know on an OID it does not give (a
             later release's) is no disagreement.
    Inputs:  present — _present's dict (name -> OID); sets — SETS' shape (default SETS).
    Returns: list of str, one per disagreement, sorted (empty: the schema agrees).
    Fails:   never.
    Feeds:   ensure_schema."""
    want = wanted_oids(sets)
    owner = {oid: name for name, oid in want.items()}
    out = []
    for name, oid in sorted(present.items()):
        if name in want and oid and oid != want[name]:
            out.append(f"{name} is {oid} here, {want[name]} in fabric")
        elif name not in want and oid in owner:
            out.append(f"{oid} is {name} here, {owner[oid]} in fabric")
    return out


def ensure_schema(conf):
    """Purpose: fabric's and sudo's attributes and classes in AD's schema (manual 1.6.3.5, 1.10.4.31), each added once
             and never changed afterwards (a schema extension is permanent: a new need is a new OID), after a check
             that the schema agrees with fabric's numbers.
    Inputs:  conf — str, the DC's smb.conf.
    Returns: list of str, the lDAPDisplayNames added (empty when the schema already has them).
    Fails:   RuntimeError "this domain's schema disagrees with fabric's: …", before anything is added; ldb.LdbError
             from an addition the schema refuses (nothing after it is added).
    Feeds:   converge.
    Notes:   two sessions, as Q3 proved necessary: the attributes, a schema reload, then (with a fresh connection)
             the classes that use them."""
    added = []
    for part in ("attributes", "classes"):
        samdb, _ = open_samdb(conf, schema_updates=True)
        schema_dn = str(samdb.get_schema_basedn())
        have = _present(samdb, schema_dn)
        if part == "attributes":
            wrong = schema_problems(have)
            if wrong:
                raise RuntimeError(f"this domain's schema disagrees with fabric's: {'; '.join(wrong)}; the domain "
                                   "ran a pre-release build: install it fresh (manual 3.2.4)")
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
            for name, n, category, must, may, *superiors in classes:
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
                    msg["possSuperiors"] = superiors[0] if superiors else ["organizationalUnit", "container"]
                    msg["defaultSecurityDescriptor"] = DEFAULT_SD
                samdb.add(msg)
                added.append(name)
        if added:
            samdb.modify_ldif("dn:\nchangetype: modify\nadd: schemaUpdateNow\nschemaUpdateNow: 1\n")
    return added
