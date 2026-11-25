from fabriclib.common.errors import ValidationError

STALE = "the split changed since it was shown; reload and try again"


def split_home(zone, split=None, old=None):
    """Purpose: where a tab's records live (decision 2.1.4.18): the zone itself for All networks, else its split.
    Inputs:  zone — the zone; split — the split's index (int or digits; None or "" for All networks); old — the
             split's networks as shown (comma-joined), checked when given, so a stale tab changes nothing.
    Returns: the dict holding the tab's record lists (and, for a split, its `subnets`).
    Fails:   ValidationError STALE: no such split, or its networks are not the ones shown.
    Feeds:   dns/add_record, dns/update_record, dns/remove_record, update_split, remove_split."""
    if split is None or split == "":
        return zone
    try:
        index = int(split)
    except (TypeError, ValueError):
        raise ValidationError(STALE)
    splits = zone.get("splits") or []
    if not 0 <= index < len(splits):
        raise ValidationError(STALE)
    if old is not None and ",".join(splits[index].get("subnets") or []) != str(old):
        raise ValidationError(STALE)
    return splits[index]
