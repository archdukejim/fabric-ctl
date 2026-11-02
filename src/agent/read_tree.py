from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.domain.browse_ou import browse_ou

KEYS = ("ou", "q", "w", "i")     # the four segments, in order, each "<key>=<value>" (never empty: 1.8.8.4)


def read_tree(segments):
    """Purpose: GET /v1/directory/tree/ou=<path>/q=<text>/w=<0|1>/i=<0|1> (manual 1.8.8.4): the directory browser's
             read. Each value is one URL-encoded segment (an OU's path holds slashes), keyed so none is empty.
    Inputs:  segments — the four segments after directory/tree, already URL-decoded.
    Returns: browse_ou's dict.
    Fails:   ValidationError "the tree's address: …" for a missing or misplaced key or a flag other than 0 or 1;
             browse_ou's.
    Feeds:   agent/get_route.py."""
    values = {}
    for key, seg in zip(KEYS, segments):
        if not seg.startswith(key + "="):
            raise ValidationError(f"the tree's address: {'/'.join(k + '=…' for k in KEYS)}")
        values[key] = seg[len(key) + 1:]
    if len(values) != len(KEYS) or values["w"] not in ("0", "1") or values["i"] not in ("0", "1"):
        raise ValidationError(f"the tree's address: {'/'.join(k + '=…' for k in KEYS)} (w and i: 0 or 1)")
    return browse_ou(load_vars(), values["ou"], values["q"], whole=values["w"] == "1", internal=values["i"] == "1")
