"""How hard the console's kept reads may work on this host (manual 1.8.9.3, decisions 2.1.8.44 and 2.1.8.51): pure
rules, read by kept_reads and fabric-agent's start."""
from collections import namedtuple

HostClass = namedtuple("HostClass", "name share lower_s upper_s held")

# a share of one core, the refresh's limits in seconds, the held processes (1.8.9.3's table)
SMALL = HostClass("small", 0.02, 30, 300, 2)
MEDIUM = HostClass("medium", 0.05, 10, 300, 4)
LARGE = HostClass("large", 0.10, 2, 300, 8)

MEMORY_FLOOR = 0.15     # the share of memory available under which a host counts as under pressure
CPU_PSI_PCT = 50.0      # /proc/pressure/cpu "some" avg60 at or over which it does: half of each minute kept off a core
MEMORY_PSI_PCT = 10.0   # /proc/pressure/memory "some" avg60 likewise: a tenth of it stalled on memory (2.3.8.9.6)
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


def psi_some_avg60(text):
    """Purpose: the "some" line's one-minute average from a /proc/pressure file (1.8.9.3).
    Inputs:  text — the file's contents, e.g. "some avg10=0.22 avg60=0.08 avg300=0.01 total=1391500408\nfull ...".
    Returns: the percentage, a float.
    Fails:   ValueError when there is no "some" line with an avg60.
    Feeds:   kept_reads.read_pressure."""
    for line in text.splitlines():
        words = line.split()
        if words and words[0] == "some":
            for word in words[1:]:
                if word.startswith("avg60="):
                    return float(word[len("avg60="):])
    raise ValueError("no some avg60 in a pressure file")


def pressure_reason(available_mb, total_mb, cpu_some=None, memory_some=None):
    """Purpose: why refreshes should slow down now, if they should (decision 2.1.8.51): the kernel's own pressure
             readings, which a load average shared with other systems on the same kernel cannot give, and little memory
             available. Without pressure readings (a kernel without PSI) memory alone decides.
    Inputs:  available_mb, total_mb — MemAvailable and MemTotal; cpu_some, memory_some — the "some" avg60 of
             /proc/pressure/cpu and /proc/pressure/memory, percent, or None when the kernel has none.
    Returns: "" when not under pressure; otherwise what is, e.g. "CPU pressure 62% (from 50%)".
    Fails:   never.
    Feeds:   KeptReads.next_wait, through kept_reads.read_pressure."""
    if memory_some is not None and memory_some >= MEMORY_PSI_PCT:
        return f"memory pressure {memory_some:g}% (from {MEMORY_PSI_PCT:g}%)"
    if cpu_some is not None and cpu_some >= CPU_PSI_PCT:
        return f"CPU pressure {cpu_some:g}% (from {CPU_PSI_PCT:g}%)"
    if available_mb < total_mb * MEMORY_FLOOR:
        return f"memory available {available_mb / total_mb:.1%} (under {MEMORY_FLOOR:.0%})"
    return ""


def held_limit(cls, dc_limit_mb):
    """Purpose: how many held processes the DC can carry: the class's number, within a share of its memory limit, and
             at least one, since a directory call needs one.
    Inputs:  cls — a HostClass; dc_limit_mb — the DC's memory limit, MB.
    Returns: int.
    Fails:   never.
    Feeds:   agent/kept_store.start_kept."""
    return max(1, min(cls.held, int(dc_limit_mb / HELD_SHARE / HELD_MB)))
