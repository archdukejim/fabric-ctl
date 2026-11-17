CRASH_SIZE = "/sys/kernel/kexec_crash_size"


def host_ram_gb(meminfo="/proc/meminfo", crash_size=CRASH_SIZE):
    """Purpose: this host's memory in GB, rounded (a 4 GB board reports a little less: 3.88 GiB on the Pi), the crash
             kernel's reservation counted in: Ubuntu Server sets aside 512 MB of a host with 4 GB or more for it, and
             MemTotal leaves it out (3.32 GiB on a 4 GB Ubuntu 26.04 VM, the 0.10.0 rc's rehearsal, 2.3.1.57).
    Inputs:  meminfo, crash_size — the files read (tests give their own).
    Returns: int, or 0 when MemTotal cannot be read (no crash file: nothing added).
    Fails:   never.
    Feeds:   setup/set_ram_capacity, deploy/render_vars (an install from before setup recorded it)."""
    try:
        with open(meminfo) as f:
            kb = next(int(line.split()[1]) for line in f if line.startswith("MemTotal:"))
    except (OSError, StopIteration, ValueError):
        return 0
    try:
        with open(crash_size) as f:
            kb += int(f.read().strip() or 0) // 1024
    except (OSError, ValueError):
        pass
    return round(kb / 1024 / 1024)
