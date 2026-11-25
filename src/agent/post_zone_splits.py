from agent.route_not_found import RouteNotFound
from fabriclib.common.errors import ValidationError
from fabriclib.dns.split.add_split import add_split
from fabriclib.dns.split.remove_split import remove_split
from fabriclib.dns.split.set_zone_networks import set_zone_networks
from fabriclib.dns.split.update_split import update_split


def _index(data):
    """Purpose: the split a change names, as an int.
    Inputs:  data — the body (split).
    Returns: int.
    Fails:   ValidationError "invalid split".
    Feeds:   post_zone_splits."""
    try:
        return int(data.get("split", -1))
    except (TypeError, ValueError):
        raise ValidationError("invalid split")


def post_zone_splits(route, actor, data):
    """Purpose: a zone's networks and splits (decision 2.1.4.18, manual 1.4.1.13): POST /v1/zones/<key>/networks
             {networks}, /v1/zones/<key>/splits {subnets}, /v1/zones/<key>/splits/update {split, old, subnets},
             /v1/zones/<key>/splits/delete {split, old} (old: the split's networks as shown, comma-joined).
    Inputs:  route — segments after /v1/; actor — the verified user; data — the body.
    Returns: set_zone_networks' {old, new}; add_split's {index, subnets}; update_split's {old, new}; the removed split.
    Fails:   ValidationError for what fabriclib refuses (-> 400); RouteNotFound for another route.
    Feeds:   agent/post_dns."""
    key, rest = route[1], route[2:]
    if rest == ["networks"]:
        return set_zone_networks(actor, key, str(data.get("networks") or ""), source="web")
    if rest == ["splits"]:
        return add_split(actor, key, str(data.get("subnets") or ""), source="web")
    if rest == ["splits", "update"]:
        return update_split(actor, key, _index(data), str(data.get("old") or ""), str(data.get("subnets") or ""),
                            source="web")
    if rest == ["splits", "delete"]:
        return remove_split(actor, key, _index(data), str(data.get("old") or ""), source="web")
    raise RouteNotFound()
