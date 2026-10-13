import ldb

from acl_entries import ensure_aces, sid_of
import paths

GROUP = "fabric-dhcp-org-editors"
# what the editors may read and write on the entry: the options (2.1.10.23) and the scan policy (2.1.10.28)
ATTRS = ("fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass", "fabricScanPolicy", "fabricScanEnforced")
POLICY_CLASS = "fabricScanPolicySet"


def _guid(samdb, name):
    """Purpose: an attribute's schemaIDGUID as an access entry names it.
    Inputs:  samdb — SamDB; name — the attribute's lDAPDisplayName.
    Returns: str, the GUID in its text form.
    Fails:   IndexError when the schema has no such attribute (ensure_schema adds them first); ldb.LdbError.
    Feeds:   ensure_org_options."""
    res = samdb.search(base=str(samdb.get_schema_basedn()), scope=ldb.SCOPE_ONELEVEL,
                       expression=f"(lDAPDisplayName={ldb.binary_encode(name)})", attrs=["schemaIDGUID"])
    return str(samdb.schema_format_value("schemaIDGUID", res[0]["schemaIDGUID"][0]), "utf-8")


def ensure_org_options(samdb):
    """Purpose: at the top site, what the organisation's DHCP options need (decision 2.1.10.23, manual 1.10.4.24.2):
             their entry `CN=dhcp-options,OU=organisation` (class fabricOptionSet, empty when made), the group
             `fabric-dhcp-org-editors` in the organisation's OU=groups (the sites whose agent the top lets edit them),
             and the group's access entries on the entry: read and write of its three option attributes and the two of
             the scan policy (2.1.10.28: the entry is given the auxiliary class fabricScanPolicySet here, as the
             editors may not add a class), nothing else. The top's own agent writes it through its full control of the
             top site's OU.
    Inputs:  samdb — SamDB (as the system).
    Returns: list of str, what changed.
    Fails:   LookupError when the organisation's OU is not there yet (ensure_layout makes it first); ldb.LdbError;
             IndexError when the schema lacks an attribute.
    Feeds:   converge (the root site only)."""
    org = paths.organisation_dn(samdb)
    dn, done = f"CN=dhcp-options,{org}", []
    if not samdb.search(base=org, scope=ldb.SCOPE_ONELEVEL,
                        expression="(&(objectClass=fabricOptionSet)(cn=dhcp-options))", attrs=["cn"]):
        samdb.add({"dn": dn, "objectClass": "fabricOptionSet",
                   "description": "fabric: the organisation's DHCP options (2.1.10.23)"})
        done.append("the organisation's DHCP options entry created")
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass"])[0]
    if POLICY_CLASS not in [str(c) for c in have["objectClass"]]:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": POLICY_CLASS}, ldb.FLAG_MOD_ADD))
        done.append("the organisation's scan policy made possible on its DHCP options entry")
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=group)(sAMAccountName={GROUP}))", attrs=["dn"])
    if not found:
        samdb.newgroup(GROUP, groupou=paths.relative(samdb, f"OU=groups,{org}"),
                       description="fabric: the sites whose agent may edit the organisation's DHCP options")
        done.append(f"group {GROUP} created")
    group = sid_of(samdb, GROUP)
    done += ensure_aces(samdb, [(dn, f"(OA;;RPWP;{_guid(samdb, attr)};;{group})") for attr in ATTRS])
    return done
