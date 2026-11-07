"""The reads fabric-agent keeps for the console (manual 1.8.9, decision 2.1.8.44): in this process's memory only."""
import os
import sys
import threading
import time

from fabriclib.common.errors import ValidationError
from fabriclib.readcache.host_rules import SMALL, pressure_reason, psi_some_avg60, refresh_interval

IDLE_S = 600            # nobody asked for this long: only the upper limit keeps a read fresh


class _Entry:
    """One read: how to make it, what it last answered, and who asked when."""

    def __init__(self, fn, lasting):
        """Purpose: a read nothing has been kept for yet.
        Inputs:  fn — callable with no arguments; lasting — one of the console's fixed pages, not one person's or
                 thing's.
        Returns: None.
        Fails:   never.
        Feeds:   KeptReads."""
        self.fn, self.lasting = fn, lasting
        self.value, self.at, self.failed = None, 0.0, ""
        self.asked, self.manual, self.tried = None, None, None


def _why_bad(value):
    """Purpose: why a read's answer must not be kept: these reads say a failure in their answer, as their pages show.
    Inputs:  value — the read's answer.
    Returns: str, "" when it may be kept.
    Fails:   never.
    Feeds:   KeptReads."""
    if not isinstance(value, dict):
        return "a read's answer is not an object"
    return str(value.get("error") or "")


def read_psi(kind, root="/proc/pressure"):
    """Purpose: one pressure reading from the kernel (1.8.9.3, decision 2.1.8.51).
    Inputs:  kind — "cpu" or "memory"; root — the folder (tests).
    Returns: its "some" avg60 percentage, or None when the kernel gives none (built without PSI, or with it off, as some
             Raspberry Pi kernels are by default).
    Fails:   never.
    Feeds:   read_pressure, pressure_source."""
    try:
        with open(os.path.join(root, kind)) as f:
            return psi_some_avg60(f.read())
    except (OSError, ValueError):
        return None


def pressure_source(root="/proc/pressure"):
    """Purpose: what this host's pressure is judged from, for the agent's status line at its start (1.8.9.3).
    Inputs:  root — the folder (tests).
    Returns: str.
    Fails:   never.
    Feeds:   agent/kept_store.start_kept."""
    if read_psi("cpu", root) is None or read_psi("memory", root) is None:
        return "no pressure readings on this kernel (PSI): pressure from available memory alone"
    return "pressure from the kernel's CPU and memory readings (PSI) and available memory"


def read_pressure(meminfo="/proc/meminfo", root="/proc/pressure"):
    """Purpose: whether this host is under pressure now, and why (host_rules.pressure_reason, from /proc).
    Inputs:  meminfo, root — where to read (tests).
    Returns: "" when not, or when /proc/meminfo cannot be read, so a refresh is never stopped by this check itself;
             otherwise the reason.
    Fails:   never.
    Feeds:   KeptReads.next_wait."""
    try:
        with open(meminfo) as f:
            info = dict(line.split(":", 1) for line in f if ":" in line)
        available, total = int(info["MemAvailable"].split()[0]), int(info["MemTotal"].split()[0])
    except (OSError, KeyError, ValueError, IndexError):
        return ""
    return pressure_reason(available / 1024, total / 1024, read_psi("cpu", root), read_psi("memory", root))


class KeptReads:
    """Purpose: what the console's slow reads last answered, served at once and refreshed apart from any request, one
             refresh at a time, so a page never waits on the DC for what was read moments ago (1.8.9.2). The route's
             permission is checked before serve is reached; what is kept never decides access.
    Feeds:   agent/kept_store, agent/get_route, agent/handler."""

    def __init__(self, cls=SMALL, clock=time.monotonic, pressure=read_pressure):
        """Purpose: an empty store for a class of host.
        Inputs:  cls — a HostClass; clock — seconds, monotonic (tests); pressure — callable() -> "" or why the host is
                 under pressure (tests).
        Returns: None.
        Fails:   never.
        Feeds:   agent/kept_store."""
        self.cls, self.clock, self.pressure = cls, clock, pressure
        self._lock, self._one = threading.Lock(), threading.Lock()
        self._wake = threading.Event()
        self._entries, self._generation, self._doubled = {}, 0, 0

    def configure(self, cls):
        """Purpose: set this host's class once it is known.
        Inputs:  cls — a HostClass.
        Returns: None.
        Fails:   never.
        Feeds:   agent/kept_store.start_kept."""
        self.cls = cls

    def register(self, key, fn):
        """Purpose: a fixed page's read, refreshed from now on though nobody has asked yet.
        Inputs:  key — hashable; fn — callable with no arguments.
        Returns: None.
        Fails:   never.
        Feeds:   agent/get_route.keep_fixed_pages."""
        with self._lock:
            self._entries.setdefault(key, _Entry(fn, True))

    def _answer(self, entry, now):
        """Purpose: what is kept, saying how old it is and whether its last refresh failed (1.8.9.4).
        Inputs:  entry — an _Entry with a value; now — the clock.
        Returns: dict: the value with "kept": {"age_s", "failed"}.
        Fails:   never.
        Feeds:   serve, refresh_now."""
        return {**entry.value, "kept": {"age_s": int(now - entry.at), "failed": entry.failed}}

    def serve(self, key, fn, lasting=True):
        """Purpose: one read for a page: what is kept, or the read made live when nothing is (1.8.9.2).
        Inputs:  key — hashable; fn — callable with no arguments, the read; lasting — False for a read naming one
                 person or thing: dropped when nobody has asked for IDLE_S.
        Returns: the answer: with "kept" when served from what was kept; as the read gave it when made live.
        Fails:   whatever fn raises, on a live read.
        Feeds:   agent/get_route."""
        now = self.clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _Entry(fn, lasting)
            idle = entry.asked is None or now - entry.asked >= IDLE_S
            entry.asked = now
            if entry.value is not None:
                if idle:                    # someone is back: read it anew now, not at the idle wait's end
                    self._wake.set()
                return self._answer(entry, now)
            generation = self._generation
        value = fn()
        if not _why_bad(value):
            with self._lock:
                if generation == self._generation:      # no change was applied while it was being read
                    entry.value, entry.at, entry.failed = value, self.clock(), ""
        return value

    def invalidate(self):
        """Purpose: a change was applied: nothing kept may be served again, and what is wanted is read anew at once.
        Inputs:  none.
        Returns: None.
        Fails:   never.
        Feeds:   agent/handler (a POST), agent/job_store (a job's end)."""
        with self._lock:
            self._generation += 1
            for entry in self._entries.values():
                entry.value, entry.failed = None, ""
        self._wake.set()

    def _due(self, entry, now):
        """Purpose: whether a read takes part in this refresh.
        Inputs:  entry — an _Entry; now — the clock.
        Returns: bool: asked for lately, or last tried as long ago as the class's upper limit allows.
        Fails:   never.
        Feeds:   refresh_all."""
        if entry.asked is not None and now - entry.asked < IDLE_S:
            return True
        return entry.tried is None or now - entry.tried >= self.cls.upper_s

    def _refresh(self, key, entry):
        """Purpose: read one entry again; a failure keeps what is there, says so on the page and in the journal.
        Inputs:  key — its key; entry — an _Entry.
        Returns: None.
        Fails:   never.
        Feeds:   refresh_all, refresh_now."""
        with self._lock:
            generation = self._generation
            entry.tried, before = self.clock(), entry.failed
        try:
            value = entry.fn()
            why = _why_bad(value)
        except Exception as exc:        # whatever a read raises must not end the refresher
            value, why = None, str(exc) or type(exc).__name__
        with self._lock:
            if generation != self._generation:
                return                  # a change was applied meanwhile: this answer may be older than it
            if why:
                entry.failed = why
            else:
                entry.value, entry.at, entry.failed = value, self.clock(), ""
        if why and why != before:       # once, not at each refresh while the DC stays down
            print(f"kept read {key} failed: {why}", file=sys.stderr, flush=True)

    def refresh_all(self):
        """Purpose: one refresh of everything due, or nothing when one is running. Reads naming one thing that nobody
                 has asked for lately are dropped.
        Inputs:  none.
        Returns: seconds it took, a float.
        Fails:   never.
        Feeds:   run; tests."""
        if not self._one.acquire(blocking=False):
            return 0.0
        began = time.monotonic()
        try:
            now = self.clock()
            with self._lock:
                for key in [k for k, e in self._entries.items() if not e.lasting
                            and (e.asked is None or now - e.asked >= IDLE_S)]:
                    del self._entries[key]
                due = [(k, e) for k, e in self._entries.items() if self._due(e, now)]
            for key, entry in due:
                self._refresh(key, entry)
        finally:
            self._one.release()
        return time.monotonic() - began

    def next_wait(self, took_s):
        """Purpose: the wait until the next refresh, doubled for each refresh in a row under pressure (1.8.9.3).
        Inputs:  took_s — the last refresh's seconds.
        Returns: seconds, a float.
        Fails:   never.
        Feeds:   run; tests."""
        before = self._doubled
        why = self.pressure()
        self._doubled = min(self._doubled + 1, 8) if why else 0
        wait = refresh_interval(took_s, self.cls, self._doubled)
        if self._doubled != before:
            state = f"under pressure, next in {wait:.0f} s: {why}" if self._doubled else "pressure over"
            print(f"kept reads: {state}", flush=True)
        return wait

    def run(self):
        """Purpose: the refresher's loop, for a thread of its own; a change applied wakes it early.
        Inputs:  none.
        Returns: never.
        Fails:   never.
        Feeds:   agent/kept_store.start_kept."""
        while True:
            wait = self.next_wait(self.refresh_all())
            self._wake.wait(wait)
            self._wake.clear()

    def refresh_now(self, key):
        """Purpose: a person's Refresh (1.8.9.4, decision 2.1.8.45): read one page's data again now, at most once per
                 the class's lower limit.
        Inputs:  key — a read's key.
        Returns: {"age_s", "failed"}: the read's state afterwards.
        Fails:   ValidationError when nothing is kept under that key, or asked again too soon (it says when).
        Feeds:   agent/post_kept."""
        now = self.clock()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise ValidationError("this page's data is read each time: there is nothing to refresh")
            if entry.manual is not None and now - entry.manual < self.cls.lower_s:
                left = int(self.cls.lower_s - (now - entry.manual)) + 1
                raise ValidationError(f"refreshed a moment ago: it can run again in {left} s")
            entry.manual = now
        with self._one:
            self._refresh(key, entry)
        with self._lock:
            if entry.value is None:
                return {"age_s": None, "failed": entry.failed}
            return self._answer(entry, self.clock())["kept"]
