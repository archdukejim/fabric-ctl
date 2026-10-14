import ldb

from acl_entries import ensure_aces, remove_aces, schema_guid, sid_of
from ensure_site_acl import HELPDESK_ATTRS, RESET_PASSWORD
import paths

IN_CHAIN = "1.2.840.113556.1.4.1941"            # LDAP_MATCHING_RULE_IN_CHAIN: nested membership counts
# the domain's own administrators, by RID under the domain SID (Domain Admins, Schema Admins, Enterprise Admins)
ADMIN_RIDS = (512, 518, 519)
BUILTIN_ADMINS = "S-1-5-32-544"                 # BUILTIN\Administrators
# a group in any site's OU=groups whose name ends so holds a role (2.1.9.13, 2.1.9.21): its members are protected
ROLE_SUFFIXES = ("-admins", "-operators", "-helpdesk", "-auditors")


def _role_groups(samdb, privileged):
    """Purpose: the DNs of every group whose members hold a role somewhere: the named fabric groups, the domain's
             own administrators, and every site's admin and role groups.
    Inputs:  samdb — SamDB; privileged — list of group names (the organisation's fabric groups).
    Returns: list of str DNs.
    Fails:   ldb.LdbError from a search.
    Feeds:   protect_privileged_people."""
    base, sid = str(samdb.domain_dn()), samdb.get_domain_sid()
    named = "".join(f"(sAMAccountName={ldb.binary_encode(n)})" for n in privileged)
    sids = "".join(f"(objectSid={sid}-{rid})" for rid in ADMIN_RIDS) + f"(objectSid={BUILTIN_ADMINS})"
    found = [str(m.dn) for m in samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                             expression=f"(&(objectClass=group)(|{named}{sids}))")]
    roles = "".join(f"(cn=*{s})" for s in ROLE_SUFFIXES)
    found += [str(m.dn) for m in samdb.search(base=paths.sites_dn(samdb), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                              expression=f"(&(objectClass=group)(|{roles}))")]
    return sorted(set(found))


def protect_privileged_people(samdb, site, privileged):
    """Purpose: the site helpdesk never reaches a person who holds a role (2.1.9.21, manual 1.6.3.18): on each person
             of the site's OU=people who is a member, nested too, of a fabric group, of the domain's administrators,
             or of any site's admin or role group, an explicit deny for `<site>-admins` of what its inherited
             helpdesk rights allow (reset password; write lockoutTime, userAccountControl, pwdLastSet) — so a local
             admin can neither take over nor lock out Central IT, another admin or each other. The denies are taken
             off a person who no longer holds a role. AD's explicit deny wins over the inherited allow.
    Inputs:  samdb — SamDB (as the system); site — str (its `<site>-admins` exists: ensure_groups); privileged —
             list of str, the organisation's fabric groups (the console's admin group and the bundle groups).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError from a search or a security descriptor change; IndexError if `<site>-admins` is missing.
    Feeds:   converge."""
    admins = sid_of(samdb, f"{site}-admins")
    denies = [f"(OD;;CR;{RESET_PASSWORD};;{admins})"]
    denies += [f"(OD;;WP;{schema_guid(samdb, a)};;{admins})" for a in HELPDESK_ATTRS]
    people = f"OU=people,{paths.site_dn(samdb, site)}"
    everyone = [str(m.dn) for m in samdb.search(base=people, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                                                expression="(&(objectCategory=person)(objectClass=user))")]
    held = set()
    for group in _role_groups(samdb, privileged):
        held |= {str(m.dn).lower() for m in samdb.search(
            base=people, scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
            expression=f"(&(objectCategory=person)(memberOf:{IN_CHAIN}:={ldb.binary_encode(group)}))")}
    done = []
    for dn in everyone:
        entries = [(dn, ace) for ace in denies]
        done += ensure_aces(samdb, entries) if dn.lower() in held else remove_aces(samdb, entries)
    return done
