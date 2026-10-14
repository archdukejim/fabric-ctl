import ldb

from acl_entries import ensure_aces, remove_aces, sid_of
from ensure_site_acl import HELPDESK_ATTRS, RESET_PASSWORD
from levels import IN_CHAIN, misplaced, role_group_dns
import paths
from schema_guid import schema_guid

# what the branch's own service accounts may not do to a person whose role reaches beyond the branch (2.1.9.24): write
# any attribute, any control access right (a password reset among them), delete, change permissions or owner
SERVICE_DENY = "WPCRSDDTWDWO"


def protect_privileged_people(samdb, site, privileged):
    """Purpose: the site helpdesk never reaches a person who holds a role (2.1.9.21, manual 1.6.3.18): on each person
             of the site's OU=people who is a member, nested too, of a fabric group, of the domain's administrators,
             or of any site's admin or role group, an explicit deny for `<site>-admins` of what its inherited
             helpdesk rights allow (reset password; write lockoutTime, userAccountControl, pwdLastSet) — so a local
             admin can neither take over nor lock out Central IT, another admin or each other. And (2.1.9.24, manual
             1.6.3.18.8) on each person there whose role reaches beyond the site — a role at a site that is not this
             one or below it, which the placement rule refuses but an older or hand-made membership may hold — an
             explicit deny for the site's own `fabric-agent-<site>` and `fabric-keycloak-<site>` of every write
             (SERVICE_DENY): root on the branch host cannot take such an account over with their credentials. Such a
             person changes their password at a sign-in page of their own level. The denies are taken off a person
             who no longer needs them. AD's explicit deny wins over the inherited allow.
    Inputs:  samdb — SamDB (as the system); site — str (its `<site>-admins` and service accounts exist: ensure_groups,
             ensure_service_accounts); privileged — list of str, the organisation's fabric groups (the console's
             admin group and the bundle groups).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a search or a security descriptor change; IndexError if a principal is missing.
    Feeds:   converge."""
    admins = sid_of(samdb, f"{site}-admins")
    denies = [f"(OD;;CR;{RESET_PASSWORD};;{admins})"]
    denies += [f"(OD;;WP;{schema_guid(samdb, a)};;{admins})" for a in HELPDESK_ATTRS]
    services = [f"(D;;{SERVICE_DENY};;;{sid_of(samdb, f'fabric-{kind}-{site}')})" for kind in ("agent", "keycloak")]
    people = f"OU=people,{paths.site_dn(samdb, site)}"
    everyone = [str(m.dn) for m in samdb.search(base=people, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                                expression="(&(objectCategory=person)(objectClass=user))")]
    held = set()
    for group in role_group_dns(samdb, privileged):
        held |= {str(m.dn).lower() for m in samdb.search(
            base=people, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
            expression=f"(&(objectCategory=person)(memberOf:{IN_CHAIN}:={ldb.binary_encode(group)}))")}
    beyond = {m["dn"].lower() for m in misplaced(samdb, site, privileged)}
    done = []
    for dn in everyone:
        entries = [(dn, ace) for ace in denies]
        done += ensure_aces(samdb, entries) if dn.lower() in held else remove_aces(samdb, entries)
        entries = [(dn, ace) for ace in services]
        done += ensure_aces(samdb, entries) if dn.lower() in beyond else remove_aces(samdb, entries)
    return done
