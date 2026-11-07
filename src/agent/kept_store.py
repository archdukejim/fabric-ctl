import os
import threading

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.directory import held_op
from fabriclib.readcache.host_rules import held_limit, host_class
from fabriclib.readcache.kept_reads import KeptReads
from fabriclib.system.memory_limit_mb import memory_limit_mb

KEPT = KeptReads()              # one per agent process; nothing is kept until start_kept runs (1.8.9.2)
_started = threading.Event()


def started():
    """Purpose: whether this process keeps reads: only a running fabric-agent does, never a test or a command.
    Inputs:  none.
    Returns: bool.
    Fails:   never.
    Feeds:   agent/get_route."""
    return _started.is_set()


def start_kept(register):
    """Purpose: size the read cache and the held processes to this host (manual 1.8.9.3, decision 2.1.8.44) and start
             the refresher. Worked out at each start, so a host given more moves class by itself.
    Inputs:  register — callable() registering the console's fixed pages (get_route.keep_fixed_pages).
    Returns: the host's class (a HostClass).
    Fails:   never: settings that cannot be read leave the Small class, the careful one.
    Feeds:   agent/server main."""
    cores = os.cpu_count() or 1
    try:
        v = load_vars()
        cls = host_class(cores, float(v.get("host_ram_capacity") or 0))
        held_op.set_limit(held_limit(cls, memory_limit_mb(v, "samba")))
    except (OSError, KeyError, TypeError, ValueError, ValidationError):
        cls = host_class(1, 0)
    KEPT.configure(cls, cores)
    register()
    _started.set()
    threading.Thread(target=KEPT.run, daemon=True, name="kept-reads").start()
    print(f"kept reads: this host is {cls.name}, {held_op.MAX_HELD} held processes", flush=True)
    return cls
