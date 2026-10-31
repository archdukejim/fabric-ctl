"""install_timers (2.3.1.32 finding 17): a timer installed now loses the stamp an earlier install left, so systemd
does not run its missed run before this install's services; a timer already installed keeps its stamp (a missed run
of a running install still runs); an optional part's timer goes when the part is off. Pure: systemctl is stubbed, the
unit and stamp folders are temporary.
    python3 tests/deploy/install_timers_test.py"""
import os
import sys
import tempfile

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.deploy.install_timers as it  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


paths = {"jinja": os.path.join(REPO, "templates")}
with tempfile.TemporaryDirectory() as units, tempfile.TemporaryDirectory() as stamps:
    for name in ("fabric-certs", "fabric-grants", "other-job"):
        open(os.path.join(stamps, f"stamp-{name}.timer"), "w").close()
    calls = []
    run = lambda args, **kw: calls.append(args)  # noqa: E731
    changed = it.install_timers(paths, {"install_resolver": True, "install_keycloak": True}, units, stamps, run)
    left = sorted(os.listdir(stamps))
    check("a first install: every timer's unit written and enabled", changed
          and all(os.path.exists(os.path.join(units, f"{n}.timer")) for n in it.TIMERS + list(it.OPTIONAL))
          and ["systemctl", "enable", "--now", "fabric-certs.timer"] in calls, (changed, calls))
    check("…and the stamps an earlier install left removed before (fabric-certs: its missed run would fire before "
          "step-ca runs)", left == ["stamp-other-job.timer"], left)
    cond = ("ExecCondition=/bin/sh -c '! systemctl is-active --quiet fabric-setup.service "
            "&& systemctl is-active --quiet fabric.target'")
    lacking = [n for n in it.TIMERS + list(it.OPTIONAL) if cond not in open(os.path.join(units, f"{n}.service")).read()]
    check("every timer's job is skipped, not failed, while setup works or fabric is stopped (finding 18)", not lacking,
          lacking)
    open(os.path.join(stamps, "stamp-fabric-certs.timer"), "w").close()
    calls.clear()
    it.install_timers(paths, {"install_resolver": True, "install_keycloak": True}, units, stamps, run)
    check("negative: an install whose timers are already there keeps their stamps (a missed run still runs)",
          os.path.exists(os.path.join(stamps, "stamp-fabric-certs.timer")), sorted(os.listdir(stamps)))
    it.install_timers(paths, {"install_resolver": False}, units, stamps, run)
    check("an optional part off: its timers disabled and their units removed",
          not os.path.exists(os.path.join(units, "fabric-dns-log.timer"))
          and ["systemctl", "disable", "--now", "fabric-dns-log.timer"] in calls, calls)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
