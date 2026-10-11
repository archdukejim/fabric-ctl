import re


def mem_mb(value):
    """Purpose: a Docker memory limit as MiB.
    Inputs:  value — "1024m", "1g", "402653184" (bytes) or None.
    Returns: float, or None when there is no limit or it does not parse.
    Fails:   never.
    Feeds:   dns_filter/check_list_memory, filter_overview."""
    m = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kmg]?)b?\s*$", str(value or "").lower())
    if not m:
        return None
    n = float(m.group(1))
    return {"": n / 1048576, "k": n / 1024, "m": n, "g": n * 1024}[m.group(2)]
