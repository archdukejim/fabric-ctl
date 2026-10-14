import ldb

from acl_entries import ensure_aces, sid_of
import paths
from schema_guid import schema_guid

GROUP = "fabric-dhcp-org-editors"
# what the editors may read and write on the entry: the options (2.1.10.23)
ATTRS = ("fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass")


def ensure_org_options(samdb):
    """Purpose: at the top site, what the organisation's DHCP options need (decision 2.1.10.23, manual 1.10.4.24.2):
             their entry `CN=dhcp-options,OU=organisation` (class fabricOptionSet, empty when made), the group
             `fabric-dhcp-org-editors` in the organisation's OU=groups (the sites whose agent the top lets edit them),
             and the group's access entries on the entry: read and write of its three option attributes, nothing else.
             The top's own agent writes it through its full control of the top site's OU. (2.1.10.28's scan policy,
             which also lived here, was removed by 2.1.10.30.)
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
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=group)(sAMAccountName={GROUP}))", attrs=["dn"])
    if not found:
        samdb.newgroup(GROUP, groupou=paths.relative(samdb, f"OU=groups,{org}"),
                       description="fabric: the sites whose agent may edit the organisation's DHCP options")
        done.append(f"group {GROUP} created")
    group = sid_of(samdb, GROUP)
    done += ensure_aces(samdb, [(dn, f"(OA;;RPWP;{schema_guid(samdb, attr)};;{group})") for attr in ATTRS])
    return done
