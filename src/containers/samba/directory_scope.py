"""Where fabric finds its people and groups since 0.9.2, when they may be in any OU (decision 2.1.6.106, manual
1.8.8.5): one rule, so nothing else names a folder for them. AD's own are whatever is not in an OU (CN=Users,
CN=Builtin), or is marked critical; a service account is whatever is in OU=service-accounts, and never a person."""
import ldb

import paths

# a person: a user account that is not a computer, and not one of AD's critical accounts (krbtgt, Administrator, Guest)
PERSON = "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(!(isCriticalSystemObject=TRUE)))"
GROUP = "(&(objectClass=group)(!(isCriticalSystemObject=TRUE)))"


def in_an_ou(samdb, dn):
    """Purpose: whether an object is in an OU of the domain (any depth), and not in AD's own containers or its Domain
             Controllers OU.
    Inputs:  samdb — SamDB; dn — str, its DN.
    Returns: bool.
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   is_person_dn, find_people, find_groups, group_kind."""
    outermost = paths.relative(samdb, dn).rsplit(",", 1)[-1].lower()
    return outermost.startswith("ou=") and outermost != "ou=domain controllers" and "," in paths.relative(samdb, dn)


def is_person_dn(samdb, dn):
    """Purpose: whether an account's place makes it a person: in an OU, and not in OU=service-accounts (manual 1.6.3.16,
             1.6.13.2).
    Inputs:  samdb — SamDB; dn — str, its DN.
    Returns: bool.
    Fails:   ValueError when dn is not inside the domain.
    Feeds:   find_people, authorize_action."""
    return in_an_ou(samdb, dn) and not dn.lower().endswith("," + paths.folder_dn(samdb, "service-accounts").lower())


def is_fabric_host_dn(samdb, dn):
    """Purpose: whether a computer is in OU=fabric-hosts, where fabric's own hosts are (manual 1.6.13.6).
    Inputs:  samdb — SamDB; dn — str, its DN.
    Returns: bool.
    Fails:   never.
    Feeds:   authorize_action, set_machine_site, set_host_group_member, adopt_linux_machines."""
    return dn.lower().endswith("," + paths.folder_dn(samdb, "fabric-hosts").lower())


def find_people(samdb, expression="", attrs=("dn",)):
    """Purpose: the domain's people wherever they are (2.1.6.106).
    Inputs:  samdb — SamDB; expression — an LDAP filter they must also match ("" for all); attrs — attributes wanted.
    Returns: list of ldb.Message.
    Fails:   ldb.LdbError from the search.
    Feeds:   find_person, list_people, save_device, set_group_managers, ensure_top_tier."""
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=list(attrs),
                         expression=f"(&{PERSON}{expression})")
    return [m for m in found if is_person_dn(samdb, str(m.dn))]


def find_groups(samdb, expression="", attrs=("dn",)):
    """Purpose: the domain's groups fabric manages wherever they are (2.1.6.106): those in an OU, never AD's own.
    Inputs:  samdb — SamDB; expression — an LDAP filter they must also match ("" for all); attrs — attributes wanted.
    Returns: list of ldb.Message.
    Fails:   ldb.LdbError from the search.
    Feeds:   list_groups, list_people, host_groups, list_host_groups."""
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=list(attrs),
                         expression=f"(&{GROUP}{expression})")
    return [m for m in found if in_an_ou(samdb, str(m.dn))]
