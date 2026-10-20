import ldb

from alloc_id import alloc_id
from grant_names import GROUP_MARK
import paths


def computed_groups(samdb):
    """Purpose: the groups in OU=fabric,OU=groups: the grants' computed groups (1.6.13.4).
    Inputs:  samdb — SamDB.
    Returns: {sAMAccountName: dn str}.
    Fails:   ldb.LdbError from the search.
    Feeds:   compile_grants."""
    return {str(m["sAMAccountName"][0]): str(m.dn)
            for m in samdb.search(base=paths.computed_groups_dn(samdb), scope=ldb.SCOPE_ONELEVEL,
                                  expression="(objectClass=group)", attrs=["sAMAccountName"])}


def ensure_computed_group(samdb, name, members, dc=None, description=GROUP_MARK):
    """Purpose: one computed group as wanted, in OU=fabric,OU=groups (1.6.13.4): created when missing, marked as
             fabric's, its members exactly `members` (anything else in it taken out); with `dc`, a POSIX group (a gid
             from that DC's built-in range, taken only when it has none), so sssd sees it (a sudo rule names it).
    Inputs:  samdb — SamDB (as the system: no one else may write OU=fabric); name — sAMAccountName; members —
             iterable of member DNs; dc — the converging DC's name (dc-NNNN) for a POSIX group, or None; description —
             str.
    Returns: list of str, what changed (counts of members added and taken out, not their names).
    Fails:   ldb.LdbError from AD; ValueError from alloc_id when the DC's range is full.
    Feeds:   compile_grants."""
    ou = paths.computed_groups_dn(samdb)
    done = []
    res = samdb.search(base=ou, scope=ldb.SCOPE_ONELEVEL, attrs=["member", "gidNumber", "description"],
                       expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    if not res:
        samdb.newgroup(name, groupou=paths.relative(samdb, ou), description=description)
        done.append(f"group {name} created")
        res = samdb.search(base=ou, scope=ldb.SCOPE_ONELEVEL, attrs=["member", "gidNumber", "description"],
                           expression=f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))")
    group = res[0]
    msg = ldb.Message(group.dn)
    if dc and not group.get("gidNumber"):
        msg["gidNumber"] = ldb.MessageElement([str(alloc_id(samdb, dc, "builtin_group"))], ldb.FLAG_MOD_REPLACE,
                                              "gidNumber")
    if str(group.get("description", [""])[0]) != description:
        msg["description"] = ldb.MessageElement([description], ldb.FLAG_MOD_REPLACE, "description")
    have = {str(ldb.Dn(samdb, str(x))).lower(): str(x) for x in group.get("member", [])}
    want = {str(ldb.Dn(samdb, m)).lower(): m for m in members}
    added, gone = [want[k] for k in want if k not in have], [have[k] for k in have if k not in want]
    if added:
        msg["member"] = ldb.MessageElement(added, ldb.FLAG_MOD_ADD, "member")
    if len(msg) > 0:
        samdb.modify(msg)
    if gone:            # in a change of its own: one element per attribute and operation
        out = ldb.Message(group.dn)
        out["member"] = ldb.MessageElement(gone, ldb.FLAG_MOD_DELETE, "member")
        samdb.modify(out)
    if added or gone:
        done.append(f"group {name}: {len(added)} added, {len(gone)} taken out")
    return done
