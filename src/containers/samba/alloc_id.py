import ldb

from id_layout import RANGES

TRIES = 50          # refused changes (another writer) and numbers found in use, together


def _in_use(samdb, number):
    """Purpose: whether a uid or gid number is already anyone's in the domain (the organisation's groups have fixed
             gids inside the root's built-in range; an admin may have set one by hand).
    Inputs:  samdb — SamDB; number — int.
    Returns: bool.
    Fails:   ldb.LdbError from the search.
    Feeds:   alloc_id."""
    return bool(samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                             expression=f"(|(uidNumber={number})(gidNumber={number}))", attrs=["dn"]))


def _take(samdb, site_dn, attr, old, new):
    """Purpose: move a high-water mark with one conditional change (delete the value read, add the next), so two
             writers cannot take the same number.
    Inputs:  samdb — SamDB; site_dn — str; attr — fabricIdMark; old, new — the values as stored.
    Returns: True when this writer moved it; False when another writer had moved it first.
    Fails:   ldb.LdbError for any other refusal.
    Feeds:   alloc_id."""
    try:
        samdb.modify_ldif(f"dn: {site_dn}\nchangetype: modify\ndelete: {attr}\n{attr}: {old}\n-\n"
                          f"add: {attr}\n{attr}: {new}\n")
        return True
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
            raise
        return False


def alloc_id(samdb, site_dn, kind="person"):
    """Purpose: the next uid/gid number of a site's block for one use, never handed out twice (2.1.6.17, 2.1.6.46,
             manual 1.6.3.9, 1.6.3.17): from the kind's fixed range, by its own high-water mark `fabricIdMark`
             "<kind>=<next>" on the site's OU (every block is laid out in ranges, id_layout.check_block). Each mark
             moves with one conditional change; a refused change is read and tried again; a number already in use is
             skipped.
    Inputs:  samdb — SamDB (the system's, or a connection as an account allowed to change the site's OU); site_dn —
             str, the site's OU; kind — a key of id_layout.RANGES: first_admin, admin, service, builtin_group, group,
             person, guest.
    Returns: int, the number taken. first_admin's one number, once taken, gives way to the admin range.
    Fails:   ValueError naming the range when it is full ("the person range 1100001-1899999 of … is full"); ValueError
             for an unknown kind, or a block whose marks are not set yet (converge first);
             ldb.LdbError after too many refused tries or for a missing OU.
    Feeds:   converge (site groups, service accounts), the directory operations (people, groups)."""
    if kind not in RANGES:
        raise ValueError(f"unknown id kind {kind!r}: one of {', '.join(RANGES)}")
    for _ in range(TRIES):
        res = samdb.search(base=site_dn, scope=ldb.SCOPE_BASE,
                           attrs=["fabricIdRange", "fabricIdMark"])[0]
        first = int(str(res["fabricIdRange"][0]).split("-")[0])
        marks = [str(m) for m in res.get("fabricIdMark", []) if str(m).startswith(f"{kind}=")]
        if not marks:
            raise ValueError(f"the {kind} range of {site_dn} has no mark yet: converge the site first")
        nxt = max(int(m.split("=", 1)[1]) for m in marks)
        lo, hi = (first + off for off in RANGES[kind])
        if nxt > hi:
            if kind == "first_admin":                       # the site has had its first admin: an admin account
                return alloc_id(samdb, site_dn, "admin")
            raise ValueError(f"the {kind.replace('_', ' ')} range {lo}-{hi} of {site_dn} is full")
        if len(marks) > 1:                                  # two writers once both added: keep the highest only
            for m in marks:
                if m != f"{kind}={nxt}":
                    try:
                        samdb.modify_ldif(f"dn: {site_dn}\nchangetype: modify\ndelete: fabricIdMark\n"
                                          f"fabricIdMark: {m}\n")
                    except ldb.LdbError:
                        pass
        if _take(samdb, site_dn, "fabricIdMark", f"{kind}={nxt}", f"{kind}={nxt + 1}") and not _in_use(samdb, nxt):
            return nxt
    raise ldb.LdbError(ldb.ERR_OTHER, f"could not take an id from {site_dn}: too many writers at once")
