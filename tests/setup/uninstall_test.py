"""uninstall's timers (2.3.1.32 finding 17): each of fabric's timers is stopped and disabled, and systemd's stamp of
its last run removed, so a later install enabling a Persistent= timer does not fire it before its services run; a
timer with no stamp is fine. Pure logic: systemctl is stubbed, the stamps are files in a temporary folder.
    python3 tests/setup/uninstall_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.uninstall as un  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


with tempfile.TemporaryDirectory() as d:
    for name in ("stamp-fabric-certs.timer", "stamp-fabric-dns-lists.timer", "stamp-apt-daily.timer"):
        open(os.path.join(d, name), "w").close()
    calls = []
    un._stop_timers(d, run=lambda args, **kw: calls.append(args))
    left = sorted(os.listdir(d))
    check("every fabric timer stopped and disabled", calls == [["systemctl", "disable", "--now", f"{t}.timer"]
                                                             for t in un.TIMERS], calls)
    check("fabric's timers' stamps removed (the renewal's included), timers with none left alone",
          left == ["stamp-apt-daily.timer"], left)
    check("negative: another program's timer stamp is kept", "stamp-apt-daily.timer" in left, left)
    check("fabric-certs (Persistent=true, daily) is one of them", "fabric-certs" in un.TIMERS, un.TIMERS)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
