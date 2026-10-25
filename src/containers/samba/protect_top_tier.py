import ldb

from acl_entries import ensure_aces, sid_of
from group_names import DIRECTORY_ADMINS
import paths

# what the Directory Administrators may not do to an object: write, create or delete below it, delete it, change its
# permissions or owner; and reset its password (the extended right User-Force-Change-Password), denied apart, so a
# person in both groups still changes their own password (User-Change-Password stays theirs)
DENY = "WPCCDCWDWOSDDTSW"
RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
# AD's top tier (2.1.6.68): Enterprise, Schema and Domain Admins (RIDs 519, 518, 512), and Administrators (S-1-5-32-544)
TOP_RIDS = (519, 518, 512)
IN_CHAIN = "1.2.840.113556.1.4.1941"          # LDAP_MATCHING_RULE_IN_CHAIN: nested membership followed


def protect_top_tier(samdb):
    """Purpose: AD's top tier out of the Directory Administrators' reach (2.1.6.68, 2.1.6.76): every account in
             fabric's OU=people or OU=service-accounts that is a member (nesting followed) of Enterprise Admins,
             Schema Admins, Domain Admins or Administrators gets an entry denying `directory-admins` any change to it,
             its password included, so their full control of the folder (inherited) never reaches it. Samba does not
             run AD's AdminSDHolder propagation, so fabric writes the deny itself.
    Inputs:  samdb — SamDB (as the system; directory-admins exists).
    Returns: list of str, the access entries added.
    Fails:   ldb.LdbError from a search or a change; IndexError when directory-admins is missing.
    Feeds:   ensure_directory_acl (every convergence), ensure_top_tier (setup's first admin, at once)."""
    base = str(samdb.domain_dn())
    sid = str(samdb.get_domain_sid())
    tops = []
    for rid in TOP_RIDS:
        found = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression=f"(objectSid={sid}-{rid})", attrs=["dn"])
        tops += [str(m.dn) for m in found]
    tops.append(f"CN=Administrators,CN=Builtin,{base}")
    chain = "".join(f"(memberOf:{IN_CHAIN}:={ldb.binary_encode(dn)})" for dn in tops)
    admins = sid_of(samdb, DIRECTORY_ADMINS)
    entries = []
    for name in ("people", "service-accounts"):
        for m in samdb.search(base=paths.folder_dn(samdb, name), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                              expression=f"(&(objectCategory=person)(|(adminCount=1){chain}))"):
            entries += [(str(m.dn), f"(D;;{DENY};;;{admins})"), (str(m.dn), f"(OD;;CR;{RESET_PASSWORD};;{admins})")]
    return ensure_aces(samdb, entries)
