from acl_entries import ensure_aces, sid_of
import paths
from schema_guid import schema_guid
from site_roles import role_group

# read, write, create and delete children, list, read permissions, delete — inherited below the OU (Q4); never
# change permissions or owner (WD, WO): a site could otherwise protect its OU from its parents' inherited access
# (2.1.6.20)
FULL = "RPWPCRCCDCLCLORCSDDTSW"
# what may not be done to a site's service accounts: write, create or delete, change permissions
SERVICE_DENY = "WPCCDCWDWOSDDT"
# the attributes a site's GPO admins write on its OU: its GPO links and its blocked inheritance (schema GUIDs)
GP_LINK, GP_OPTIONS = "f30e3bbe-9ff0-11d1-b603-0000f80367c1", "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
COMPUTER = "bf967a86-0de6-11d0-a285-00aa003049e2"     # the computer class's schemaIDGUID
HOST_KEY = "fabricSshHostKey"                         # a machine publishes its SSH host keys here (1.6.11.9.7)
# set from above, never by the site itself (2.1.10.30): whether its own admins may scan, on its OU; a scan request,
# created only by a site above in the site's plan
LOCAL_SCAN_ATTRS, SCAN_REQUEST = ("fabricLocalScan", "fabricLocalScanBy"), "fabricScanRequest"


def _top_down(samdb, site, site_dn):
    """Purpose: the access entries that keep a site's scans top down (decision 2.1.10.30, manual 1.10.4.29.2): its own
             agent and OU admins denied writing the local-scan setting on its OU (explicit, not inherited: evaluated
             before the full control they inherit there, and the site still sets it on the sites below it) and denied
             creating a scan request in its own OU=networks (inherited by its subnets' entries). The sites above keep
             their inherited full control, so they set it and ask.
    Inputs:  samdb — SamDB; site — str; site_dn — its OU.
    Returns: list of (dn, SDDL entry) for ensure_aces.
    Fails:   IndexError when the schema lacks the attributes or the class (ensure_schema adds them first);
             ldb.LdbError.
    Feeds:   ensure_site_acl (every site but the root)."""
    entries = []
    for principal in (role_group(site, "ou-admins"), f"fabric-agent-{site}"):
        sid = sid_of(samdb, principal)
        entries += [(site_dn, f"(OD;;WP;{schema_guid(samdb, attr)};;{sid})") for attr in LOCAL_SCAN_ATTRS]
        entries.append((f"OU=networks,{site_dn}", f"(OD;CI;CC;{schema_guid(samdb, SCAN_REQUEST)};;{sid})"))
    return entries


def ensure_site_acl(samdb, site, root):
    """Purpose: who may write what in a site (S2, 2.1.9.13, manual 1.6.3.6), checked by every DC, offline too (Q4, Q12):
             its `<site>-ou-admins` and its fabric-agent account have full control below the site's OU, inherited
             (so into the sites nested below it, 2.1.6.20); its `<site>-machine-admins` full control of its machines and
             devices; its `<site>-gpo-admins` its OU's GPO links and blocked inheritance (their own GPOs: admin_gpo);
             none of them over permissions, nor over its own or a nested site's service accounts; its Keycloak account
             full control of the site's people only (sign-in changes passwords and lockouts), and at the root site
             the members of the organisation's groups (Keycloak's group mapper); each computer account below its
             OU=machines may write its own SSH host keys (SELF, fabricSshHostKey only: manual 1.6.11.9.7), nothing
             else of fabric's; and below the root, its agent and OU admins denied what the sites above decide for it
             (_top_down: its local-scan setting, a scan request in its plan, 2.1.10.30).
    Inputs:  samdb — SamDB; site — str (its groups and service accounts exist: ensure_groups,
             ensure_service_accounts); root — bool.
    Returns: list of str, the access entries added.
    Fails:   ldb.LdbError reading a principal or changing a security descriptor; IndexError if one is missing.
    Feeds:   converge."""
    site_dn = paths.site_dn(samdb, site)
    services = f"OU=service-accounts,{site_dn}"
    entries = []
    for principal in (role_group(site, "ou-admins"), f"fabric-agent-{site}"):
        entries.append((site_dn, f"(A;CI;{FULL};;;{sid_of(samdb, principal)})"))
    machines = sid_of(samdb, role_group(site, "machine-admins"))
    entries += [(f"OU={ou},{site_dn}", f"(A;CI;{FULL};;;{machines})") for ou in ("machines", "devices")]
    # a machine publishes its own SSH host keys: SELF (PS) may write that one attribute, on computer objects only
    entries.append((f"OU=machines,{site_dn}", f"(OA;CIIO;WP;{schema_guid(samdb, HOST_KEY)};{COMPUTER};PS)"))
    gpo = sid_of(samdb, role_group(site, "gpo-admins"))
    entries += [(site_dn, f"(OA;;RPWP;{attr};;{gpo})") for attr in (GP_LINK, GP_OPTIONS)]
    # the service accounts are fabric's: no one's inherited access reaches them, this site's or a parent's
    for owner in [site] + paths.ancestors(samdb, site):
        for principal in (role_group(owner, "ou-admins"), role_group(owner, "machine-admins"), f"{owner}-admins",
                          f"fabric-agent-{owner}"):
            entries.append((services, f"(D;CI;{SERVICE_DENY};;;{sid_of(samdb, principal)})"))
    keycloak = sid_of(samdb, f"fabric-keycloak-{site}")
    entries.append((f"OU=people,{site_dn}", f"(A;CI;{FULL};;;{keycloak})"))
    if root:            # Keycloak's group mapper writes memberships of the organisation's groups (LDAP_ONLY)
        entries.append((f"OU=groups,{paths.organisation_dn(samdb)}", f"(A;CI;RPWPLCLORC;;;{keycloak})"))
    else:               # scans are set and asked from above (2.1.10.30): the root has no site above it
        entries += _top_down(samdb, site, site_dn)
    return ensure_aces(samdb, entries)
