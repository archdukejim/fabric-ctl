"""The ranges inside a site's uid/gid block (2.1.6.46, manual 1.6.3.17): offsets from the block's start, the same at
every site. Every site's block is laid out this way: a million ids starting on a multiple of a million (a block from
before 0.7.0, handed out in one run, is no longer served: none exists, 2.1.6.51, stale code S11)."""

BLOCK = 1_000_000
# kind: (first offset, last offset), both inclusive
RANGES = {
    "first_admin": (0, 0),                  # the site's first admin (setup's first admin at the root)
    "admin": (1, 19_999),                   # site admins, operators' privileged identities
    "service": (20_001, 39_999),            # fabric's per-site domain accounts, service identities admins make
    "builtin_group": (40_001, 49_999),      # fabric's built-in groups: the organisation's at the root, each site's own
    "group": (50_001, 99_999),              # groups admins make
    "person": (100_001, 899_999),           # people
    "guest": (900_001, 949_999),            # guests and temporary accounts
}                                           # 950001-999999: reserved (machines' POSIX ids, should NFS need them)
# the first hundred of the built-in range hold fabric's fixed gids (the organisation's groups, at the root: from
# 040001), so a site's own built-in groups are handed out from 040101
MARK_START = {**{kind: first for kind, (first, _) in RANGES.items()}, "builtin_group": 40_101}


def check_block(id_range):
    """Purpose: a site's uid/gid block checked before anything is written (2.1.6.46, manual 1.6.3.17): a million ids
             starting on a multiple of a million, so the fixed ranges fit it.
    Inputs:  id_range — str "first-last".
    Returns: (first, last), both int.
    Fails:   ValueError naming the block: malformed, or not a site block (e.g. an install's from before 0.7.0: the
             message says it is installed fresh for 0.8.0, decision 2.1.6.54).
    Feeds:   converge (first, before the schema and the layout), ensure_site_info."""
    try:
        first, last = (int(x) for x in str(id_range).split("-"))
    except ValueError:
        raise ValueError(f"id range {id_range!r}: first-last, two whole numbers") from None
    if first <= 0 or first % BLOCK or last - first + 1 != BLOCK:
        raise ValueError(f"id range {id_range!r} is not a site's block: a million ids from a multiple of a million "
                         "(2.1.6.46). Such a block comes from an install made before 0.7.0, which 0.8.0 does not "
                         "upgrade: install it fresh (there is no migration of ids before 1.0, 2.1.1.31; the steps: "
                         "manual 3.3.5)")
    return first, last
