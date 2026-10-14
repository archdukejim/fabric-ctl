import ldb

from acl_entries import ensure_aces, owner_of, schema_guid, sid_of
import paths
from site_roles import grant_group, grantable, role_group

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
RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"  # the control access right User-Force-Change-Password
# what the site's helpdesk (`<site>-admins`, 2.1.9.21) writes on its people: unlock, disable or enable, must-change
HELPDESK_ATTRS = ("lockoutTime", "userAccountControl", "pwdLastSet")
# what a branch's own fabric-agent account and `<site>-ou-admins` may not do to the site's role groups (2.1.9.21,
# revised 2026-10-13): write any attribute (members, name), delete, delete the tree, change permissions or owner
ROLE_GROUP_DENY = "WPSDDTWDWO"


def _exists(samdb, dn):
    """Purpose: whether an entry exists.
    Inputs:  samdb — SamDB; dn — str.
    Returns: bool.
    Fails:   ldb.LdbError other than no such object.
    Feeds:   ensure_site_acl."""
    try:
        samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["dn"])
        return True
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise


def _check_owners(samdb, groups, branch):
    """Purpose: refuse to give a role's rights to a group the branch itself made (2.1.9.21, revised 2026-10-13): its
             agent or `<site>-ou-admins` may still delete a role group through their right to delete children of the
             OU, and make one of the same name with themselves as its owner; convergence would then grant the new
             group the role's rights by name. A group fabric made is owned by the domain's administrators (the
             system, or a site above's agent for a console role it granted).
    Inputs:  samdb — SamDB; groups — list of DN str (existing); branch — {sid: name} of the branch's own principals.
    Returns: None.
    Fails:   PermissionError naming the group and its owner (convergence stops loudly; from a site above it is reported
             for that site); ldb.LdbError reading a security descriptor.
    Feeds:   ensure_site_acl."""
    for dn in groups:
        owner = owner_of(samdb, dn)
        if owner in branch:
            raise PermissionError(f"{dn.split(',')[0][3:]} was made by {branch[owner]}, not by fabric: a role group a "
                                  "branch re-made is not given the role's rights (2.1.9.21). Delete it as a domain "
                                  "administrator, then make it again as manual 4.9.1.2 says")


def ensure_site_acl(samdb, site, root):
    """Purpose: who may write what in a site (S2, 2.1.9.13, manual 1.6.3.6), checked by every DC, offline too (Q4, Q12):
             its `<site>-ou-admins` and its fabric-agent account have full control below the site's OU, inherited
             (so into the sites nested below it, 2.1.6.20); its `<site>-machine-admins` full control of its machines and
             devices; its `<site>-gpo-admins` its OU's GPO links and blocked inheritance (their own GPOs: admin_gpo);
             none of them over permissions, nor over its own or a nested site's service accounts; its Keycloak account
             full control of the site's people only (sign-in changes passwords and lockouts), and at the root site
             the members of the organisation's groups (Keycloak's group mapper); and each computer account below its
             OU=machines may write its own SSH host keys (SELF, fabricSshHostKey only: manual 1.6.11.9.7), nothing
             else of fabric's. Its `<site>-admins`, the site helpdesk (2.1.9.21, manual 1.6.3.18): exactly what
             unlocking, resetting a password, adding and disabling the site's own people need — create user objects in
             its OU=people; on the users there (inherit-only) reset password, write lockoutTime, userAccountControl and
             pwdLastSet; write the members of `<site>-users` (a new person joins it); nothing else (a person who holds
             a role is kept from it: protect_privileged_people). Below the root, neither `<site>-admins` nor
             `<site>-ou-admins` may write the members of the site's grantable role groups or of `<site>-admins` (an
             explicit deny: a branch cannot grant itself; a site above can, through its inherited rights). Its own
             fabric-agent account and `<site>-ou-admins` are also denied every other write on those groups (their
             name, deleting them, their permissions and owner: ROLE_GROUP_DENY), so root on a branch host cannot
             grant through the agent's credentials either; a role group the branch re-made (owned by one of them) is
             refused before any right is given to it (_check_owners). Grants come only from a site above's agent.
    Inputs:  samdb — SamDB; site — str (its groups and service accounts exist: ensure_groups,
             ensure_service_accounts); root — bool.
    Returns: list of str, the access entries added.
    Fails:   ldb.LdbError reading a principal or changing a security descriptor; IndexError if one is missing;
             PermissionError for a role group the branch re-made (_check_owners).
    Feeds:   converge."""
    site_dn = paths.site_dn(samdb, site)
    services = f"OU=service-accounts,{site_dn}"
    entries = []
    protected = [] if root else [dn for dn in (f"CN={name},OU=groups,{site_dn}" for name in
                                               [grant_group(site, r) for r in grantable()] + [f"{site}-admins"])
                                 if _exists(samdb, dn)]     # a site below not converged to 0.9 lacks its console roles
    branch = {sid_of(samdb, n): n for n in (f"fabric-agent-{site}", role_group(site, "ou-admins"), f"{site}-admins")}
    _check_owners(samdb, protected, branch)
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
    admins = sid_of(samdb, f"{site}-admins")        # the site helpdesk (2.1.9.21)
    people, user = f"OU=people,{site_dn}", schema_guid(samdb, "user")
    entries.append((people, f"(OA;CI;CC;{user};;{admins})"))
    entries.append((people, f"(OA;CIIO;CR;{RESET_PASSWORD};{user};{admins})"))
    entries += [(people, f"(OA;CIIO;RPWP;{schema_guid(samdb, a)};{user};{admins})") for a in HELPDESK_ATTRS]
    member = schema_guid(samdb, "member")
    entries.append((f"CN={site}-users,OU=groups,{site_dn}", f"(OA;;RPWP;{member};;{admins})"))
    # only a site above grants a site's roles: its own admins, OU admins and agent are denied the memberships, and the
    # OU admins and agent every other write on those groups (none at the root: Central IT grants there)
    ou_admins, agent = sid_of(samdb, role_group(site, "ou-admins")), sid_of(samdb, f"fabric-agent-{site}")
    for group in protected:
        entries += [(group, f"(OD;;WP;{member};;{sid})") for sid in (admins, ou_admins, agent)]
        entries += [(group, f"(D;;{ROLE_GROUP_DENY};;;{sid})") for sid in (ou_admins, agent)]
    if root:            # Keycloak's group mapper writes memberships of the organisation's groups (LDAP_ONLY)
        entries.append((f"OU=groups,{paths.organisation_dn(samdb)}", f"(A;CI;RPWPLCLORC;;;{keycloak})"))
    return ensure_aces(samdb, entries)
