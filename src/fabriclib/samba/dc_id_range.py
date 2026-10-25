import re

from fabriclib.common.errors import ValidationError
from fabriclib.samba.suggested_dc_name import MAX_DCS

BLOCK = 1_000_000
DC_NAME = re.compile(r"^dc-(\d{4})$")


def dc_id_range(dc):
    """Purpose: the uid/gid range a DC's number gives it (2.1.6.63, 2.1.6.86; manual 1.6.5.26): DC N owns N x 1000000
             to N x 1000000 + 999999, as the DC's own code lays it out (src/containers/samba/id_layout.py, which
             fabriclib cannot import: it runs inside the DC). No setting, nothing to agree.
    Inputs:  dc — the DC's name, `dc-0001` to `dc-1999` (any case).
    Returns: str "first-last", e.g. "2000000-2999999" for dc-0002.
    Fails:   ValidationError for a name that is not a numbered DC's.
    Feeds:   federation/accept_join (the range a joining DC is given, by the name it is given; the registry shows
             it)."""
    m = DC_NAME.match(str(dc or "").strip().lower())
    if not m or not 1 <= int(m.group(1)) <= MAX_DCS:
        raise ValidationError(f"{dc!r} is not a numbered DC name (dc-0001 to dc-{MAX_DCS}): its number gives its id "
                              "range (2.1.6.63)")
    first = int(m.group(1)) * BLOCK
    return f"{first}-{first + BLOCK - 1}"
