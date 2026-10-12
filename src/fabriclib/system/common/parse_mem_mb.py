import re

from fabriclib.common.errors import ValidationError

UNITS = {"": 1 / (1024 * 1024), "b": 1 / (1024 * 1024), "k": 1 / 1024, "m": 1, "g": 1024}


def parse_mem_mb(value, key):
    """Purpose: a Docker memory size as whole MB (manual 1.2.4.3): what a `*_mem_limit` setting holds.
    Inputs:  value — "384m", "1g", "512M", "1.5g", an int (bytes, as Docker reads a bare number) or None/""; key — the
             setting it came from, named in the refusal.
    Returns: int MB (rounded down), or None for None / "".
    Fails:   ValidationError for a value that is not a size, or one under 1 MB.
    Feeds:   system/plan_memory, system/memory_limit_mb."""
    if value is None or value == "":
        return None
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([bkmg]?)b?\s*$", str(value).lower())
    if isinstance(value, bool) or not m:
        raise ValidationError(f"{key}: {value!r} is not a memory size such as 256m or 1g")
    mb = int(float(m.group(1)) * UNITS[m.group(2)])
    if mb < 1:
        raise ValidationError(f"{key}: {value!r} is under 1 MB")
    return mb
