import re

import ldb
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.sd_utils import SDUtils

from find_gpo import find_gpo
from grant_names import APPLY_GROUP_POLICY, AUTHENTICATED_USERS
from set_gpo_acl import set_gpo_acl

OBJECT_ALLOWED = security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT


def _key(text, domain_sid):
    """Purpose: what one access entry grants to whom, comparable (Samba may write an entry in another form or order).
    Inputs:  text — one entry in SDDL, "(A;CI;…;;;S-…)"; domain_sid — security.dom_sid.
    Returns: tuple (type, flags, mask, trustee SID, object type or "").
    Fails:   RuntimeError for invalid SDDL.
    Feeds:   set_gpo_filter."""
    sd = security.descriptor.from_sddl("D:" + text, domain_sid)
    ace = sd.dacl.aces[0]
    obj = str(ace.object.type) if ace.type == OBJECT_ALLOWED else ""
    return (ace.type, ace.flags, ace.access_mask, str(ace.trustee), obj)


def set_gpo_filter(samdb, lp, name, group_sid, machine_sids=()):
    """Purpose: a GPO's security filtering, as GPMC sets it (manual 1.6.13.4; checked on sssd, 2.3.6.19.1):
             Authenticated Users keep Read (every machine reads it), and only `group_sid` gets Read and Apply Group
             Policy; with no group, Authenticated Users apply it (every machine, the fallback, 2.1.6.87). Each of
             `machine_sids` (the group's computers) also gets Apply Group Policy on its own SID, for sssd before 2.9.4,
             which ignores the computer's groups (2.1.6.94). Every other Apply Group Policy entry is taken out (a
             machine that left the group too). SYSVOL's file ACLs follow. Nothing is written when it is already so.
    Inputs:  samdb — SamDB (as the system); lp — LoadParm; name — the GPO's display name; group_sid — str, or None;
             machine_sids — iterable of str, the computers' SIDs (only with a group).
    Returns: list of str, what changed.
    Fails:   ValueError "no GPO <name>"; ldb.LdbError; NTSTATUSError from set_gpo_acl.
    Feeds:   compile_grants."""
    found = find_gpo(samdb, name)
    if found is None:
        raise ValueError(f"no GPO {name}")
    dn, guid, _ = found
    domain_sid = security.dom_sid(samdb.get_domain_sid())
    res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"])
    sddl = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0]).as_sddl(domain_sid)
    head, rest = sddl.split("D:", 1)
    sacl = ""
    if "S:" in rest:
        rest, sacl = rest.split("S:", 1)
        sacl = "S:" + sacl
    flags = re.match(r"^[A-Z]*", rest).group(0)
    target = group_sid or AUTHENTICATED_USERS
    want = [f"(A;CI;RPLCLORC;;;{AUTHENTICATED_USERS})", f"(OA;CI;CR;{APPLY_GROUP_POLICY};;{target})"]
    if group_sid:
        want.insert(1, f"(A;CI;RPLCLORC;;;{group_sid})")
        want += [f"(OA;CI;CR;{APPLY_GROUP_POLICY};;{sid})" for sid in sorted(set(machine_sids))]
    keep, drop = [], []
    for ace in re.findall(r"\([^)]*\)", rest):
        k = _key(ace, domain_sid)
        mine = k[3] in (AUTHENTICATED_USERS, target) or (k[0] == OBJECT_ALLOWED and k[4] == APPLY_GROUP_POLICY)
        (drop if mine and not k[1] & security.SEC_ACE_FLAG_INHERITED_ACE else keep).append(ace)
    if sorted(_key(a, domain_sid) for a in drop) == sorted(_key(a, domain_sid) for a in want):
        return []
    new = security.descriptor.from_sddl(head + "D:" + flags + "".join(keep + want) + sacl, domain_sid)
    SDUtils(samdb).modify_sd_on_dn(dn, new, controls=["sd_flags:1:4"])
    set_gpo_acl(samdb, lp, guid)
    return [f"GPO {name}: applies to " + (f"its group's machines alone ({len(set(machine_sids))} named)"
                                          if group_sid else "every machine")]
