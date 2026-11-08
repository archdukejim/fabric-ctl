#!/usr/bin/env python3
"""The console's read cache with no container (manual 1.8.9, decisions 2.1.8.43 to 2.1.8.45): the host's classes at each
edge of the table, the refresh's interval, pressure, what is kept and what never is, a change applied, a failed refresh
and Refresh's limit. The real components are in tests/sandbox/read_cache.py.

    python3 tests/speed/read_cache.py
"""
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

from agent import get_route as m_get  # noqa: E402
from agent import kept_store as m_store  # noqa: E402
from agent.post_kept import post_kept  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.readcache.host_rules import LARGE, MEDIUM, SMALL, held_limit, host_class, pressure_reason, \
    psi_some_avg60, refresh_interval  # noqa: E402
from fabriclib.readcache.kept_reads import IDLE_S, KeptReads, pressure_source, read_pressure  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"  -> {detail}" if not cond else ""))
    FAILED += 0 if cond else 1


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Read:
    def __init__(self, value=None):
        self.value, self.calls, self.raises = value if value is not None else {"n": 0}, 0, None

    def __call__(self):
        self.calls += 1
        if self.raises:
            raise self.raises
        return {**self.value, "n": self.calls}


def store(cls=SMALL, pressure=False):
    clock = Clock()
    return KeptReads(cls, clock=clock, pressure=lambda: "CPU pressure 60% (from 50%)" if pressure else ""), clock


# ---- the host's classes: the table's edges (1.8.9.3)
for cores, ram, want in [(4, 4, SMALL), (4, 8, SMALL), (4, 100, SMALL), (5, 7, SMALL), (5, 8, MEDIUM), (7, 31, MEDIUM),
                         (8, 31, MEDIUM), (5, 32, MEDIUM), (7, 100, MEDIUM), (8, 32, LARGE), (16, 100, LARGE),
                         (1, 1, SMALL), (64, 7, SMALL)]:
    check(f"{cores} cores, {ram} GB: {want.name}", host_class(cores, ram) is want, host_class(cores, ram).name)
check("the table's numbers: small", SMALL[1:] == (0.02, 30, 300, 2), SMALL)
check("the table's numbers: medium", MEDIUM[1:] == (0.05, 10, 300, 4), MEDIUM)
check("the table's numbers: large", LARGE[1:] == (0.10, 2, 300, 8), LARGE)

# ---- the interval follows the work, within the class's limits
check("a quick refresh on a Pi waits the lower limit", refresh_interval(0.1, SMALL) == 30)
check("1 s on a Pi at 2% of a core waits 50 s", refresh_interval(1.0, SMALL) == 50)
check("a long refresh on a Pi waits the upper limit", refresh_interval(60, SMALL) == 300)
check("a quick refresh on a large host waits 2 s", refresh_interval(0.05, LARGE) == 2)
check("1 s on a large host at 10% waits 10 s", refresh_interval(1.0, LARGE) == 10)
check("1 s on a medium host at 5% waits 20 s", refresh_interval(1.0, MEDIUM) == 20)
check("under pressure the wait doubles", refresh_interval(0.1, SMALL, 1) == 60 and refresh_interval(0.1, SMALL, 2) == 120)
check("and never passes the upper limit", refresh_interval(0.1, SMALL, 8) == 300 and refresh_interval(0.1, LARGE, 8) == 300)

# ---- pressure: each side of each line
# (2.1.8.51): the kernel's pressure readings and available memory, never the load average
check("memory at 15%, CPU and memory pressure under their lines: none", pressure_reason(150, 1000, 49.99, 9.99) == "")
check("memory under 15%: pressure", pressure_reason(149, 1000, 0, 0) == "memory available 14.9% (under 15%)",
      pressure_reason(149, 1000, 0, 0))
check("CPU pressure at 50%: pressure, saying so", pressure_reason(900, 1000, 50, 0) == "CPU pressure 50% (from 50%)")
check("memory pressure at 10%: pressure, saying so", pressure_reason(900, 1000, 0, 10) == "memory pressure 10% (from 10%)")
check("gaming-23's WSL (load 211 on 24 cores, CPU 0.08%, memory 0.02%, 86% free): no pressure",
      pressure_reason(27597, 31936, 0.08, 0.02) == "")
check("no pressure readings (a kernel without PSI): memory alone decides",
      pressure_reason(900, 1000) == "" and pressure_reason(100, 1000).startswith("memory available"))
PSI = "some avg10=0.22 avg60=0.08 avg300=0.01 total=1391500408\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
check("a pressure file's some avg60 is read, not its full line", psi_some_avg60(PSI) == 0.08)
for bad in ("", "full avg10=1 avg60=2 avg300=3 total=4\n", "some avg10=1 avg300=3\n", "some avg60=x\n"):
    try:
        psi_some_avg60(bad)
        check(f"refused: a pressure file without a some avg60 ({bad!r})", False)
    except ValueError:
        check(f"refused: a pressure file without a some avg60 ({bad!r})", True)
with tempfile.TemporaryDirectory() as tmp:
    mem = os.path.join(tmp, "meminfo")
    psi = os.path.join(tmp, "pressure")
    with open(mem, "w") as f:
        f.write("MemTotal:  1024000 kB\nMemFree: 900 kB\nMemAvailable:  512000 kB\n")
    check("PSI missing: no pressure from a half-free host, and the status says memory alone",
          read_pressure(mem, psi) == "" and "alone" in pressure_source(psi), pressure_source(psi))
    os.mkdir(psi)
    with open(os.path.join(psi, "cpu"), "w") as f:
        f.write(PSI.replace("avg60=0.08", "avg60=72.5"))
    check("PSI half there (no memory file): the status says memory alone", "alone" in pressure_source(psi))
    with open(os.path.join(psi, "memory"), "w") as f:
        f.write(PSI)
    check("PSI there: the reason read from the files, the status naming them",
          read_pressure(mem, psi) == "CPU pressure 72.5% (from 50%)" and "PSI" in pressure_source(psi)
          and "alone" not in pressure_source(psi), (read_pressure(mem, psi), pressure_source(psi)))
    with open(os.path.join(psi, "cpu"), "w") as f:
        f.write("garbled\n")
    check("a pressure file that cannot be read counts as absent, never as pressure", read_pressure(mem, psi) == "")
    check("a meminfo that cannot be read: no pressure, so the check never stops a refresh by itself",
          read_pressure(os.path.join(tmp, "none"), psi) == "")
kept, _ = store(pressure=True)
check("pressure in a row doubles each time", [kept.next_wait(0.1) for _ in range(3)] == [60, 120, 240])
kept.pressure = lambda: ""
check("and ends when it does", kept.next_wait(0.1) == 30)

# ---- held processes: the class's number, within the DC's memory limit
check("a Pi's 512 MiB DC: 2", held_limit(SMALL, 512) == 2)
check("a Pi's 648 MiB DC: 2", held_limit(SMALL, 648) == 2)
check("a medium host needs 880 MiB for its 4", held_limit(MEDIUM, 880) == 4 and held_limit(MEDIUM, 879) == 3)
check("a large host's 2 GiB DC: 8", held_limit(LARGE, 2048) == 8)
check("a large class with a small DC limit is held to it", held_limit(LARGE, 512) == 2)
check("never none", held_limit(SMALL, 64) == 1)

# ---- what is kept
kept, clock = store()
read = Read()
first = kept.serve("sites", read)
check("nothing kept: read live, and it says nothing of age", read.calls == 1 and "kept" not in first, first)
clock.now += 20
again = kept.serve("sites", read)
check("then served without reading, saying its age", read.calls == 1 and again["kept"] == {"age_s": 20, "failed": ""}, again)
kept.refresh_all()
fresh = kept.serve("sites", read)
check("a refresh replaces it", read.calls == 2 and fresh["n"] == 2 and fresh["kept"]["age_s"] == 0, fresh)

bad = Read({"error": "the DC is down"})
out = kept.serve("broken", bad)
check("a read that says it failed is shown as it is and not kept",
      out["error"] == "the DC is down" and "kept" not in out and kept.serve("broken", bad)["n"] == 2)
for value in ([1, 2], "text"):
    kept2, _ = store()
    fn = lambda v=value: v  # noqa: E731
    check(f"an answer that is no object is not kept ({type(value).__name__})",
          kept2.serve("x", fn) == value and kept2.serve("x", fn) == value)

# ---- a change applied
kept, clock = store()
read = Read()
kept.serve("sites", read)
kept.invalidate()
out = kept.serve("sites", read)
check("after a change nothing old is served: read live", read.calls == 2 and "kept" not in out, out)

kept, clock = store()
read = Read()
kept.serve("sites", read)
slow = Read()


def changes_during_read():
    kept.invalidate()
    return slow()


kept.serve("during", changes_during_read)
check("an answer read while a change was applied is not kept",
      kept._entries["during"].value is None)
read.calls = 0
kept.serve("sites", read)
check("nor is what was kept before it served", read.calls == 1)

entry_read = Read()
kept, clock = store()
kept.serve("a", entry_read)


def invalidate_then_read():
    kept.invalidate()
    return {"late": True}


kept._entries["a"].fn = invalidate_then_read
kept.refresh_all()
check("a refresh overtaken by a change is thrown away", kept._entries["a"].value is None)

# ---- a failed refresh keeps what is there, and says so
kept, clock = store()
read = Read()
kept.serve("sites", read)
read.raises = ValidationError("the domain controller is not running")
clock.now += 40
kept.refresh_all()
out = kept.serve("sites", read)
check("a failed refresh: old data, its true age, and why", out["n"] == 1 and out["kept"]["age_s"] == 40
      and "not running" in out["kept"]["failed"], out)
read.raises = None
kept.refresh_all()
out = kept.serve("sites", read)
check("the next good refresh clears it", out["kept"]["failed"] == "" and out["kept"]["age_s"] == 0, out)
read = Read({"error": "no answer"})
kept, clock = store()
good = Read()
kept.serve("sites", good)
good.value = {"error": "the directory could not be read"}
kept.refresh_all()
out = kept.serve("sites", good)
check("a refresh answering with an error keeps the old too", "error" not in out and out["kept"]["failed"], out)

# ---- what is refreshed
kept, clock = store()
asked, fixed = Read(), Read()
kept.serve("asked", asked)
kept.register("fixed", fixed)
kept.refresh_all()
check("a registered page is read before anyone asks", fixed.calls == 1 and asked.calls == 2)
kept.refresh_all()
check("then not again while nobody asks for it", fixed.calls == 1 and asked.calls == 3)
clock.now += LARGE.upper_s
kept.refresh_all()
check("until the upper limit", fixed.calls == 2)
clock.now += IDLE_S
calls = asked.calls
kept.refresh_all()
check("a page nobody asked for lately waits for the upper limit too", asked.calls == calls + 1)
calls = asked.calls
kept.refresh_all()
check("and is then left alone", asked.calls == calls)
person = Read()
kept.serve(("people", "x"), person, lasting=False)
clock.now += IDLE_S
kept.refresh_all()
check("one person's page nobody asked for is dropped", ("people", "x") not in kept._entries)
check("a fixed page is not", "fixed" in kept._entries)

kept, clock = store()
kept.serve("back", Read())
kept._wake.clear()
kept.serve("back", Read())
check("asked again soon: the refresher is left to its time", not kept._wake.is_set())
clock.now += IDLE_S
kept.serve("back", Read())
check("asked after a long idle: what is kept is served and the refresher woken", kept._wake.is_set())

# ---- one refresh at a time
kept, clock = store()
started, release = threading.Event(), threading.Event()
slow = Read()


def blocked():
    started.set()
    release.wait(10)
    return slow()


kept.register("slow", blocked)
worker = threading.Thread(target=kept.refresh_all)
worker.start()
started.wait(10)
check("a second refresh does nothing while one runs", kept.refresh_all() == 0.0 and slow.calls == 0)
release.set()
worker.join(10)
check("the first one finished", slow.calls == 1)

# ---- Refresh (2.1.8.45)
kept, clock = store(SMALL)
read = Read()
try:
    kept.refresh_now("nothing")
    check("negative: nothing kept under that name is refused", False)
except ValidationError as exc:
    check("negative: nothing kept under that name is refused, saying why", "nothing to refresh" in str(exc), exc)
kept.serve("sites", read)
clock.now += 50
out = kept.refresh_now("sites")
check("Refresh reads again now", read.calls == 2 and out == {"age_s": 0, "failed": ""}, out)
clock.now += 29
try:
    kept.refresh_now("sites")
    check("negative: again within the class's lower limit is refused", False)
except ValidationError as exc:
    check("negative: again within the class's lower limit is refused, saying when", "again in 2 s" in str(exc)
          and read.calls == 2, exc)
clock.now += 1
out = kept.refresh_now("sites")
check("at the lower limit it runs", read.calls == 3, out)
read.raises = ValidationError("no DC")
clock.now += 30
out = kept.refresh_now("sites")
check("a failed Refresh says why", "no DC" in out["failed"], out)
kept, clock = store(LARGE)
read = Read()
kept.serve("sites", read)
kept.refresh_now("sites")
clock.now += 2
kept.refresh_now("sites")
check("a large host's limit is its own", read.calls == 3)

# ---- the agent's routes (the whole path is in tests/sandbox/read_cache.py)
reads = {"n": 0}


def counted():
    reads["n"] += 1
    return {"n": reads["n"]}


m_get.READS[("sites",)] = counted
out = m_get.get_route(["sites"], "pat", {"domain:read"})
out = m_get.get_route(["sites"], "pat", {"domain:read"})
check("not a running agent: always live", reads["n"] == 2 and "kept" not in out, out)
m_store._started.set()
m_get.KEPT.configure(SMALL)
m_get.get_route(["sites"], "pat", {"domain:read"})
out = m_get.get_route(["sites"], "pat", {"domain:read"})
check("a signed-in person: from what is kept", reads["n"] == 3 and "kept" in out, out)
out = m_get.get_route(["sites"], None, None)
check("the host itself (a root peer): live", reads["n"] == 4 and "kept" not in out, out)
# covers: agent:post.kept.refresh +
out = post_kept({"read": "sites"}, {"domain:read"}, "pat")
check("POST /v1/kept/refresh reads again", reads["n"] == 5 and out["age_s"] == 0, out)
for body, perms, words in [({"read": "sites"}, {"domain:read"}, "again in"), ({"read": ""}, None, "which page"),
                           ({}, None, "which page"), ({"read": "../etc"}, None, "no such read"),
                           ({"read": "no/such/route"}, None, "no such read"),
                           ({"read": "sites"}, {"status:read"}, "you need the permission domain:read"),
                           ({"read": "audit"}, None, "nothing to refresh")]:
    before = reads["n"]
    try:
        post_kept(body, perms, "pat")
        check(f"negative: {body} refused", False)
    except ValidationError as exc:
        # covers: agent:post.kept.refresh -
        check(f"negative: {body} refused ({words}), nothing read", words in str(exc) and reads["n"] == before, exc)
m_get.READS[("overview",)] = lambda: {"services": [], "reminders": []}
m_get.READS[("updates",)] = lambda: {"rows": []}
# covers: agent:get.overview +
check("GET /v1/overview", set(m_get.get_route(["overview"], None, None)) == {"services", "reminders"})
# covers: agent:get.updates +
check("GET /v1/updates", m_get.get_route(["updates"], None, None) == {"rows": []})
# covers: agent:get.overview -
check("GET /v1/overview needs status:read", required_permission("GET", ["overview"]) == "status:read")
# covers: agent:get.updates -
check("GET /v1/updates needs status:read", required_permission("GET", ["updates"]) == "status:read")
check("POST /v1/kept/refresh needs a session", required_permission("POST", ["kept", "refresh"]) == "session")
check("no secret's read is kept", not [k for k in m_get.KEPT_FIXED if k[0] in ("vault", "secrets")], m_get.KEPT_FIXED)
sys.exit(1 if FAILED else 0)
