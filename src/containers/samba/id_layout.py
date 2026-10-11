"""The ranges inside a site's uid/gid block (2.1.6.46, manual 1.6.3.17): offsets from the block's start, the same at
every site. A block laid out this way is a million ids starting on a multiple of a million; a block from before
0.7.0 (the root's from 5001, sites' after it) is not, and hands out its ids in one run as it always did."""

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


def laid_out(first, last):
    """Purpose: whether a block has the fixed ranges (a new install's from 0.7.0) or is one run (an older install's).
    Inputs:  first, last — int, the block's ends.
    Returns: bool: a million ids starting on a multiple of a million.
    Fails:   never.
    Feeds:   alloc_id, ensure_site_info, site_info."""
    return first % BLOCK == 0 and last - first + 1 == BLOCK
