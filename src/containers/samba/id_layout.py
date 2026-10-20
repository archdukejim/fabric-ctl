"""The id ranges of the domain's DCs (2.1.6.63, 2.1.6.86, manual 1.6.5.26): DC N (`dc-NNNN`, 1 to 1999) owns N x
1 000 000 to N x 1 000 000 + 999 999, and every DC's range is laid out in the same fixed ranges (2.1.6.46): offsets from
its start, by kind."""
import re

BLOCK = 1_000_000
MAX_DC = 1999                               # dc-1999's range ends at 1 999 999 999: every id below 2 000 000 000
DC_NAME = re.compile(r"^dc-(\d{4})$")
# kind: (first offset, last offset), both inclusive
RANGES = {
    "first_admin": (0, 0),                  # setup's first admin (dc-0001's)
    "admin": (1, 19_999),                   # admins, operators' privileged identities
    "service": (20_001, 39_999),            # fabric's per-DC domain accounts, service identities admins make
    "builtin_group": (40_001, 49_999),      # fabric's built-in groups
    "group": (50_001, 99_999),              # groups admins make
    "person": (100_001, 899_999),           # people
    "guest": (900_001, 949_999),            # guests and temporary accounts
}                                           # 950001-999999: reserved (machines' POSIX ids, should NFS need them)
# the first hundred of the built-in range hold fabric's fixed gids (the organisation's groups, in dc-0001's: from
# 1040001), so a DC's own built-in groups are handed out from 040101
MARK_START = {**{kind: first for kind, (first, _) in RANGES.items()}, "builtin_group": 40_101}


def dc_range(dc):
    """Purpose: the id range a DC's number gives it (2.1.6.63, 2.1.6.86): no setting, nothing to agree.
    Inputs:  dc — the DC's name, `dc-0001` to `dc-1999` (any case).
    Returns: str "first-last", e.g. "1000000-1999999" for dc-0001.
    Fails:   ValueError naming the name: not dc-NNNN, or a number outside 1 to 1999 (a DC named otherwise is an
             install from before 0.8.0, which is installed fresh: there is no upgrade, 2.1.1.60).
    Feeds:   ensure_dc_record, converge (checked before anything is written)."""
    m = DC_NAME.match(str(dc or "").strip().lower())
    if not m or not 1 <= int(m.group(1)) <= MAX_DC:
        raise ValueError(f"DC name {dc!r} is not one of the domain's numbered names, dc-0001 to dc-{MAX_DC}: its "
                         "number gives its id range (2.1.6.63). A DC named otherwise comes from an install made "
                         "before 0.8.0, which 0.8.0 does not upgrade: install it fresh (manual 3.3.5)")
    first = int(m.group(1)) * BLOCK
    return f"{first}-{first + BLOCK - 1}"


def check_block(id_range):
    """Purpose: a range as a DC's record holds it, checked: a million ids starting on a multiple of a million, so the
             fixed ranges fit it (2.1.6.46).
    Inputs:  id_range — str "first-last".
    Returns: (first, last), both int.
    Fails:   ValueError naming the range: malformed, or not a DC's.
    Feeds:   ensure_dc_record, alloc_id."""
    try:
        first, last = (int(x) for x in str(id_range).split("-"))
    except ValueError:
        raise ValueError(f"id range {id_range!r}: first-last, two whole numbers") from None
    if first <= 0 or first % BLOCK or last - first + 1 != BLOCK or first // BLOCK > MAX_DC:
        raise ValueError(f"id range {id_range!r} is not a DC's: a million ids from N x 1000000, N from 1 to "
                         f"{MAX_DC} (2.1.6.63)")
    return first, last
