"""How hard the console's kept reads may work on this host (manual 1.8.9.3, decision 2.1.8.44): pure rules, read by
kept_reads and fabric-agent's start."""
from collections import namedtuple

HostClass = namedtuple("HostClass", "name share lower_s upper_s held")

# a share of one core, the refresh's limits in seconds, the held processes (1.8.9.3's table)
SMALL = HostClass("small", 0.02, 30, 300, 2)
MEDIUM = HostClass("medium", 0.05, 10, 300, 4)
LARGE = HostClass("large", 0.10, 2, 300, 8)

MEMORY_FLOOR = 0.15     # the share of memory available under which a host counts as under pressure
HELD_MB = 110           # a held process's memory in the DC, its highest as measured (2.3.8.9.3)
HELD_SHARE = 2          # held processes may take half of the DC's memory limit


def host_class(cores, ram_gb):
    """Purpose: the class of a host (1.8.9.3): both figures must reach a class to be in it.
    Inputs:  cores — int; ram_gb — host_ram_capacity, GB.
    Returns: SMALL, MEDIUM or LARGE.
    Fails:   never.
    Feeds:   agent/kept_store.start_kept."""
    if ram_gb >= 32 and cores >= 8:
        return LARGE
    if ram_gb >= 8 and cores >= 5:
        return MEDIUM
    return SMALL


def refresh_interval(took_s, cls, doubled=0):
    """Purpose: the wait until the next refresh: the last one's time over the class's share of a core, held between
             the class's limits; doubled while the host is under pressure, never past the upper limit.
    Inputs:  took_s — seconds the last refresh took; cls — a HostClass; doubled — how many times over to double.
    Returns: seconds, a float.
    Fails:   never.
    Feeds:   KeptReads.next_wait."""
    wanted = max(cls.lower_s, min(cls.upper_s, took_s / cls.share))
    return float(min(cls.upper_s, wanted * 2 ** doubled))


def under_pressure(available_mb, total_mb, load, cores):
    """Purpose: whether refreshes should slow down: little memory available, or more runnable work than cores.
    Inputs:  available_mb, total_mb — MemAvailable and MemTotal; load — the one-minute load average; cores — int.
    Returns: bool.
    Fails:   never.
    Feeds:   KeptReads.next_wait; read_pressure."""
    return available_mb < total_mb * MEMORY_FLOOR or load > cores


def held_limit(cls, dc_limit_mb):
    """Purpose: how many held processes the DC can carry: the class's number, within a share of its memory limit, and
             at least one, since a directory call needs one.
    Inputs:  cls — a HostClass; dc_limit_mb — the DC's memory limit, MB.
    Returns: int.
    Fails:   never.
    Feeds:   agent/kept_store.start_kept."""
    return max(1, min(cls.held, int(dc_limit_mb / HELD_SHARE / HELD_MB)))
