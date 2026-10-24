"""The zones a running BIND does not know though fabric has their files (`dns/zones_bind_lacks`, 2.3.10.11.16): a
zone list installed by an apply that stopped before `rndc reconfig`. Pure logic: docker exec stood in for (the
`zones` suite asks a real BIND). In the `zone` suite.
    python3 tests/dns/zones_bind_lacks_test.py"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.dns.zones_bind_lacks import zones_bind_lacks  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def answering(stdout, seen=None):
    def run(cmd, **kw):
        if seen is not None:
            seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout, "")
    return run


def raising(exc):
    def run(cmd, **kw):
        raise exc
    return run


with tempfile.TemporaryDirectory() as d:
    for name in ("db.lan.test", "db.10.88.30.in-addr.arpa", "db.lan.test.jnl", "named.conf"):
        open(os.path.join(d, name), "w").close()
    seen = []
    got = zones_bind_lacks(d, run=answering("10.88.30.in-addr.arpa\n", seen))
    check("positive: a zone BIND answers 'not found' for is named; one call for every zone, journals not zones",
          got == ["10.88.30.in-addr.arpa"] and len(seen) == 1
          and seen[0][-2:] == ["10.88.30.in-addr.arpa", "lan.test"], (got, seen))
    check("positive: BIND knows every zone: none named", zones_bind_lacks(d, run=answering("")) == [])
    check("negative: a line that is no zone of the list is not taken",
          zones_bind_lacks(d, run=answering("evil.example\n")) == [])
    check("negative: docker missing (OSError): none named, no error",
          zones_bind_lacks(d, run=raising(OSError("no docker"))) == [])
    check("negative: BIND not answering in time: none named",
          zones_bind_lacks(d, run=raising(subprocess.TimeoutExpired("docker", 60))) == [])
with tempfile.TemporaryDirectory() as d:
    called = []
    check("negative: no zone files: BIND not asked", zones_bind_lacks(d, run=answering("", called)) == [] and not called)
check("negative: the folder missing: none named", zones_bind_lacks("/nonexistent/fabric-zones") == [])

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
