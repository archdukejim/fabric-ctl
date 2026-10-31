import ldb

from acl_entries import ensure_aces, sid_of
from group_names import DIRECTORY_ADMINS, TIERS
import paths
from protect_top_tier import DENY, RESET_PASSWORD, protect_top_tier

# read, write, create and delete children, list, read permissions, control access, delete — inherited below; never
# change permissions or owner (WD, WO), so no holder can lift the denies below
FULL = "RPWPCRCCDCLCLORCSDDTSW"
READ = "RPLCLORC"
# the attributes a GPO is linked by on an OU: its GPO links and its blocked inheritance (schema GUIDs)
GP_LINK, GP_OPTIONS = "f30e3bbe-9ff0-11d1-b603-0000f80367c1", "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
# the folders the Directory Administrators hold, and their GPO links (2.1.6.76)
ADMIN_FOLDERS = ("people", "service-accounts", "machines", "groups")
# the folders fabric-agent writes (people, groups, machines, devices, ...): never OU=service-accounts (Q4)
AGENT_FOLDERS = ("people", "groups", "machines", "fabric-hosts", "devices", "device-roles", "networks", "sudoers")
# fabric's own accounts in OU=service-accounts: out of the Directory Administrators' reach
FABRIC_ACCOUNTS = "(&(objectCategory=person)(|(sAMAccountName=fabric-agent-*)(sAMAccountName=fabric-keycloak-*)" \
                  "(sAMAccountName=fabric-radius-*)(sAMAccountName=fabric-sso-*)(sAMAccountName=fabric-join-*)))"


def ensure_directory_acl(samdb, dc):
    """Purpose: who may write what in the directory, in AD's own ACLs, checked by every DC, offline too (2.1.6.68,
             2.1.6.76; manual 1.6.13.2): the Directory Administrators (`directory-admins`) have full control of
             OU=people, OU=service-accounts, OU=machines and OU=groups and everything below, and may link GPOs there,
             so RSAT works for them as the console does; never over permissions (WD, WO), fabric's own service
             accounts, the tiers' groups (`directory-admins`, `dc-hosts`), the grants' computed groups (OU=fabric in
             OU=groups) or AD's top tier (protect_top_tier); nothing on AD's own containers, the Domain Controllers OU
             or OU=fabric-hosts. This DC's fabric-agent account has full control of fabric's folders but
             OU=service-accounts, and of fabric's state (CN=fabric,CN=System, 2.1.6.79), which every authenticated
             account reads; its Keycloak account full control of OU=people (sign-in changes passwords and lockouts) and
             the members of OU=groups (Keycloak's group mapper). The grants' computed groups are written by no account
             at all: every one (Everyone) is denied any change in OU=fabric, the agents' and Keycloak's accounts and
             the top tier too; fabric's compile writes them inside the DC as the system (1.6.13.4).
    Inputs:  samdb — SamDB (as the system; this DC's service accounts and fabric's groups exist: ensure_groups,
             ensure_service_accounts); dc — the DC whose accounts are given their rights (the converging DC, or the one
             prepared).
    Returns: list of str, the access entries added.
    Fails:   ldb.LdbError reading a principal or changing a security descriptor; IndexError if one is missing.
    Feeds:   converge."""
    folder = lambda name: paths.folder_dn(samdb, name)      # noqa: E731
    admins = sid_of(samdb, DIRECTORY_ADMINS)
    agent = sid_of(samdb, f"fabric-agent-{dc}")
    keycloak = sid_of(samdb, f"fabric-keycloak-{dc}")
    entries = []
    for name in ADMIN_FOLDERS:
        entries.append((folder(name), f"(A;CI;{FULL};;;{admins})"))
        entries += [(folder(name), f"(OA;CI;RPWP;{attr};;{admins})") for attr in (GP_LINK, GP_OPTIONS)]
    entries.append((paths.computed_groups_dn(samdb), f"(D;CI;{DENY};;;{admins})"))
    entries.append((paths.computed_groups_dn(samdb), f"(D;CI;{DENY};;;WD)"))      # nobody: the compile is the system
    groups = folder("groups")
    for name in TIERS:
        entries.append((f"CN={name},{groups}", f"(D;;{DENY};;;{admins})"))
    services = folder("service-accounts")
    for account in samdb.search(base=services, scope=ldb.SCOPE_SUBTREE, expression=FABRIC_ACCOUNTS, attrs=["dn"]):
        entries += [(str(account.dn), f"(D;;{DENY};;;{admins})"),
                    (str(account.dn), f"(OD;;CR;{RESET_PASSWORD};;{admins})")]
    entries += [(folder(name), f"(A;CI;{FULL};;;{agent})") for name in AGENT_FOLDERS]
    entries.append((paths.fabric_dn(samdb), f"(A;CI;{FULL};;;{agent})"))
    entries.append((paths.fabric_dn(samdb), f"(A;CI;{READ};;;AU)"))
    entries.append((folder("people"), f"(A;CI;{FULL};;;{keycloak})"))
    entries.append((groups, f"(A;CI;RPWPLCLORC;;;{keycloak})"))
    return ensure_aces(samdb, entries) + protect_top_tier(samdb)
