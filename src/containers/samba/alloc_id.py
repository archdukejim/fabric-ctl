import ldb

from id_layout import RANGES
import paths

TRIES = 50          # refused changes (another writer) and numbers found in use, together


class _Full(Exception):
    """A record's range of one kind has no number left (alloc_id then tries the site's other DCs)."""


def _in_use(samdb, number):
    """Purpose: whether a uid or gid number is already anyone's in the domain (the organisation's groups have fixed
             gids inside dc-0001's built-in range; an admin may have set one by hand).
    Inputs:  samdb — SamDB; number — int.
    Returns: bool.
    Fails:   ldb.LdbError from the search.
    Feeds:   _take_from."""
    return bool(samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                             expression=f"(|(uidNumber={number})(gidNumber={number}))", attrs=["dn"]))


def _move(samdb, dn, old, new):
    """Purpose: move a high-water mark with one conditional change (delete the value read, add the next), so two
             writers cannot take the same number.
    Inputs:  samdb — SamDB; dn — the DC's record; old, new — the fabricIdMark values as stored.
    Returns: True when this writer moved it; False when another writer had moved it first.
    Fails:   ldb.LdbError for any other refusal.
    Feeds:   _take_from."""
    try:
        samdb.modify_ldif(f"dn: {dn}\nchangetype: modify\ndelete: fabricIdMark\nfabricIdMark: {old}\n-\n"
                          f"add: fabricIdMark\nfabricIdMark: {new}\n")
        return True
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
            raise
        return False


def _take_from(samdb, dn, kind):
    """Purpose: the next number of one kind from one DC's record, by its mark.
    Inputs:  samdb — SamDB; dn — the DC's record; kind — a key of RANGES.
    Returns: int.
    Fails:   _Full when the kind's range of this record is used up (its message names the range); ValueError for a
             record whose marks are not set yet (converge first); ldb.LdbError after too many refused tries.
    Feeds:   alloc_id."""
    for _ in range(TRIES):
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["fabricIdRange", "fabricIdMark"])[0]
        first = int(str(res["fabricIdRange"][0]).split("-")[0])
        marks = [str(m) for m in res.get("fabricIdMark", []) if str(m).startswith(f"{kind}=")]
        if not marks:
            raise ValueError(f"the {kind} range of {dn} has no mark yet: converge the DC first")
        nxt = max(int(m.split("=", 1)[1]) for m in marks)
        lo, hi = (first + off for off in RANGES[kind])
        if nxt > hi:
            raise _Full(f"{lo}-{hi}")
        if len(marks) > 1:                                  # two writers once both added: keep the highest only
            for m in marks:
                if m != f"{kind}={nxt}":
                    try:
                        samdb.modify_ldif(f"dn: {dn}\nchangetype: modify\ndelete: fabricIdMark\nfabricIdMark: {m}\n")
                    except ldb.LdbError:
                        pass
        if _move(samdb, dn, f"{kind}={nxt}", f"{kind}={nxt + 1}") and not _in_use(samdb, nxt):
            return nxt
    raise ldb.LdbError(ldb.ERR_OTHER, f"could not take an id from {dn}: too many writers at once")


def alloc_id(samdb, dc, kind="person"):
    """Purpose: the next uid/gid number for one use, never handed out twice (2.1.6.63, 2.1.6.46; manual 1.6.5.26,
             1.6.3.17): from the kind's fixed range of the DC's own record (`fabricIdMark` "<kind>=<next>" on
             CN=<dc>,CN=dcs,CN=fabric,CN=System), and once that range is full from the same range of its site's other
             DCs, in name order. A read-only DC's ids are taken at its writable partner, from its own record (2.1.6.85).
             Each mark moves with one conditional change; a refused change is read and tried again; a number already
             in use is skipped.
    Inputs:  samdb — SamDB (the system's, or a connection as one of fabric's agent accounts); dc — the DC's name
             (dc-NNNN); kind — a key of id_layout.RANGES: first_admin, admin, service, builtin_group, group, person,
             guest.
    Returns: int, the number taken. first_admin's one number, once taken, gives way to the admin range.
    Fails:   ValueError naming the ranges when every one is full ("the person range 1100001-1899999 of dc-0001 is
             full, and so are its site's other DCs'"); ValueError for an unknown kind, or a record whose marks are not
             set yet; ldb.LdbError for a DC with no record, or after too many refused tries.
    Feeds:   converge (fabric's groups, the service accounts), the directory operations (people)."""
    if kind not in RANGES:
        raise ValueError(f"unknown id kind {kind!r}: one of {', '.join(RANGES)}")
    own = paths.dc_record_dn(samdb, dc)
    try:
        return _take_from(samdb, own, kind)
    except _Full as full:
        if kind == "first_admin":                           # the first admin is made: an admin account
            return alloc_id(samdb, dc, "admin")
        first = str(full)
    site = samdb.search(base=own, scope=ldb.SCOPE_BASE, attrs=["fabricSite"])[0].get("fabricSite", [""])[0]
    others = samdb.search(base=f"CN=dcs,{paths.fabric_dn(samdb)}", scope=ldb.SCOPE_ONELEVEL, attrs=["cn"],
                          expression=f"(&(objectClass=fabricDcInfo)(fabricSite={ldb.binary_encode(str(site))}))")
    for other in sorted((str(m["cn"][0]) for m in others), key=str.lower):
        if other.lower() == dc.lower():
            continue
        try:
            return _take_from(samdb, paths.dc_record_dn(samdb, other), kind)
        except _Full:
            continue
    raise ValueError(f"the {kind.replace('_', ' ')} range {first} of {dc} is full, and so are its site's other DCs'")
