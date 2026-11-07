import ldb

from group_kind import group_kind
from group_names import DC_HOSTS
import paths

ENTERPRISE_ADMIN = "fabric-admin"         # the Enterprise Admin, break glass (2.1.6.68)
FIXED_GROUPS = ("ad", "computed", "tier", "fabric", "filled", "bundle")   # group_kind's kinds fabric keeps where it is


def own_object(samdb, msg, bundles=()):
    """Purpose: why an object is fabric's own (or AD's) and stays where it is (decision 2.1.6.100, 1.8.8.5): the fabric
             hosts (OU=fabric-hosts, or in dc-hosts) and the DCs, fabric's service accounts and its Enterprise Admin,
             the tiers', bundles', computed, filled and fabric's own groups, AD's own groups, and any object AD marks
             critical (isCriticalSystemObject). Every other person, machine and group may be moved.
    Inputs:  samdb — SamDB; msg — an ldb.Message of the object (only its DN is read; the rest is read here);
             bundles — the names of the groups carrying a fabric role bundle (the settings' ldap_groups).
    Returns: str, what it is ("a fabric host", ...), or "" when it may be moved.
    Fails:   ldb.LdbError from a search.
    Feeds:   move_object, set_machine_type."""
    dn = str(msg.dn)
    low = dn.lower()
    one = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                       attrs=["objectClass", "sAMAccountName", "memberOf", "isCriticalSystemObject"])[0]
    classes = {str(c).lower() for c in one.get("objectClass", [])}
    name = str(one.get("sAMAccountName", [""])[0])
    if str(one.get("isCriticalSystemObject", ["FALSE"])[0]).upper() == "TRUE":
        return "one of AD's own objects"
    if "computer" in classes:
        hosts = paths.folder_dn(samdb, "fabric-hosts").lower()
        if low.endswith("," + hosts) or any(str(g).lower().startswith(f"cn={DC_HOSTS},")
                                           for g in one.get("memberOf", [])):
            return "a fabric host"
        return ""
    if "group" in classes:
        kind = group_kind(samdb, name, bundles)["kind"]
        return f"one of fabric's {kind} groups" if kind in FIXED_GROUPS else ""
    if "user" in classes:
        services = paths.folder_dn(samdb, "service-accounts").lower()
        if name.lower() == ENTERPRISE_ADMIN or (low.endswith("," + services) and name.lower().startswith("fabric-")):
            return "one of fabric's own accounts"
    return ""
