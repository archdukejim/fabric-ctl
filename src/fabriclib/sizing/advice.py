"""The sizing advice's model (manual 1.8.8.8, decision 2.1.8.36): what an install of a size needs, against the host.
Pure:
no reads, no writes. Its numbers are `table.py`'s, measured (2.3.8.5)."""
import math

from fabriclib.sizing.table import TABLE

RESOURCES = ("ram", "cores", "disk", "dc_memory")
CLOSE = {"ram": "add memory to the host",
         "cores": "move the install to a host with more CPU cores",
         "disk": "free space on fabric's data volume, or give it more",
         "dc_memory": "raise samba_mem_limit in the settings, or give the host more memory (manual 1.2.4.3)"}
WHAT = {"ram": "RAM", "cores": "CPU cores", "disk": "free disk",
        "dc_memory": "of memory limit for the domain controller"}


def objects_of(size):
    """Purpose: the count that drives the model: what the domain controller holds.
    Inputs:  size — {"people", "computers", "groups"}.
    Returns: int.
    Fails:   never (a missing count is 0).
    Feeds:   needed, sizing_alerts."""
    return sum(int(size.get(k) or 0) for k in ("people", "computers", "groups"))


def needed(size, table=TABLE):
    """Purpose: the minimum and the recommended of each resource for an install of a size: a fixed part plus a part per
             directory object (a straight line, manual 1.8.8.8).
    Inputs:  size — {"people", "computers", "groups"}; table — the fit.
    Returns: {resource: (minimum, recommended)}, in MiB for memory and disk, in cores (whole) for cores.
    Fails:   KeyError for a table without a resource (a coding error).
    Feeds:   sizing_alerts, tests."""
    n = objects_of(size)
    out = {}
    for res in RESOURCES:
        row = table[res]
        low, high = row["min"] + row["min_per"] * n, row["rec"] + row["rec_per"] * n
        out[res] = (math.ceil(low), math.ceil(high)) if res == "cores" else (round(low), round(high))
    return out


def _amount(res, value):
    """Purpose: an amount as the alert says it.
    Inputs:  res — one of RESOURCES; value — number (MiB, or cores).
    Returns: str ("8.0 GB", "512 MiB", "4 cores").
    Fails:   never.
    Feeds:   sizing_alerts."""
    if res == "cores":
        return f"{int(value)} core{'' if int(value) == 1 else 's'}"
    return f"{value / 1024:.1f} GB" if value >= 1024 else f"{int(value)} MiB"


def _people(size):
    """Purpose: the install's size in words, as the owner's example has it.
    Inputs:  size — {"people", ...}.
    Returns: str ("1,000 people").
    Fails:   never.
    Feeds:   sizing_alerts."""
    count = int(size.get("people") or 0)
    return f"{count:,} {'person' if count == 1 else 'people'}"


def sizing_alerts(size, host, table=TABLE):
    """Purpose: what the install's administrators are told (manual 1.8.8.8): below the recommended value a warning,
             below the minimum critical; exactly at a value is not below it. A resource the host could not say is left
             out, never guessed.
    Inputs:  size — {"people", "computers", "groups"}; host — {"ram", "cores", "disk", "dc_memory"} (MiB, or cores; None
             or missing when unknown); table — the fit.
    Returns: list of {"resource", "level" ("warn"|"critical"), "have", "minimum", "recommended", "gap" (recommended less
             what it has), "what" (the sentence), "close" (what would close it)}, critical first.
    Fails:   never.
    Feeds:   refresh_sizing, tests."""
    want = needed(size, table)
    out = []
    for res in RESOURCES:
        have = host.get(res)
        if have is None:
            continue
        low, high = want[res]
        if have >= high:
            continue
        gap = high - have
        out.append({"resource": res, "level": "critical" if have < low else "warn", "have": have, "minimum": low,
                    "recommended": high, "gap": gap,
                    "what": (f"{_people(size)} on {_amount(res, have)} {WHAT[res]}: {_amount(res, gap)} below the "
                             f"recommended {_amount(res, high)} for that size"
                             + (f", and below the minimum {_amount(res, low)}" if have < low else "")),
                    "close": CLOSE[res]})
    return sorted(out, key=lambda a: (a["level"] != "critical", RESOURCES.index(a["resource"])))


def visible_alerts(alerts, dismissed, size):
    """Purpose: one person's alerts: those they have not dismissed, or dismissed and now with something new to say: the
             install grown by another 10% since (at least one object), or the level crossed from warn to critical
             (decision 2.1.8.39).
    Inputs:  alerts — sizing_alerts' list; dismissed — {resource: {"level", "objects"}}, this person's; size — as above.
    Returns: list, of alerts.
    Fails:   never.
    Feeds:   read_sizing, tests."""
    n = objects_of(size)
    out = []
    for a in alerts:
        was = dismissed.get(a["resource"])
        if was is None or (was["level"] == "warn" and a["level"] == "critical"):
            out.append(a)
        elif n >= was["objects"] + max(1, math.ceil(was["objects"] * 0.1)):
            out.append(a)
    return out
