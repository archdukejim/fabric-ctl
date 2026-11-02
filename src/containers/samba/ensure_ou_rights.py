import ldb

from acl_entries import ensure_aces, sid_of
from group_names import DIRECTORY_ADMINS
from ou_paths import is_admin_ou

# as ensure_directory_acl's: full control below (never WD, WO) and the attributes a GPO is linked by
FULL = "RPWPCRCCDCLCLORCSDDTSW"
GP_LINK, GP_OPTIONS = "f30e3bbe-9ff0-11d1-b603-0000f80367c1", "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
# organizationalUnit's schema GUID: the one child the root's entry lets them create
OU_CLASS = "bf967aa5-0de6-11d0-a285-00aa003049e2"


def _root_ous(samdb):
    """Purpose: the admins' own OUs directly at the domain's root (each one's own below inherit from it).
    Inputs:  samdb — SamDB.
    Returns: list of str, their DNs.
    Fails:   ldb.LdbError from the search.
    Feeds:   ensure_ou_rights."""
    res = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_ONELEVEL,
                       expression="(objectClass=organizationalUnit)", attrs=["dn"])
    return [str(m.dn) for m in res if is_admin_ou(samdb, str(m.dn))]


def ensure_ou_rights(samdb, dc, only=None):
    """Purpose: the admins' rights on their own OUs wherever they are (decision 2.1.6.102, manual 1.8.8.5): on the
             domain's root, the Directory Administrators and this DC's fabric-agent may create an OU and nothing else
             (an entry on the root alone, never inherited, so nothing lands on AD's own containers); on each admin's
             OU at the root (made by fabric or with RSAT), the Directory Administrators' full control and GPO links and
             the agent's full control, inherited by what is below it, as on fabric's folders (ensure_directory_acl).
             An OU below fabric's folders inherits them already and gets nothing of its own.
    Inputs:  samdb — SamDB (as the system; or, with only, as the agent that just made that OU: its owner);
             dc — the DC whose fabric-agent account is given its rights; only — one OU's DN: that OU's entries alone.
    Returns: list of str, the access entries added.
    Fails:   ldb.LdbError reading a principal or changing a security descriptor; IndexError if one is missing.
    Feeds:   ensure_directory_acl (each convergence), compile_grants (each compile: an OU made with RSAT),
             create_ou (one fabric made at the root)."""
    admins = sid_of(samdb, DIRECTORY_ADMINS)
    agent = sid_of(samdb, f"fabric-agent-{dc}")
    entries = []
    if only is None:
        root = str(samdb.domain_dn())
        entries += [(root, f"(OA;;CC;{OU_CLASS};;{who})") for who in (admins, agent)]
    for dn in ([only] if only else _root_ous(samdb)):
        entries.append((dn, f"(A;CI;{FULL};;;{admins})"))
        entries += [(dn, f"(OA;CI;RPWP;{attr};;{admins})") for attr in (GP_LINK, GP_OPTIONS)]
        entries.append((dn, f"(A;CI;{FULL};;;{agent})"))
    return ensure_aces(samdb, entries, dacl_only=bool(only))
