"""sssd's socket units (1.6.7.8, 2.1.6.95): the host's own join masks them as the Linux join does (one glob, the same
commands: this test fails if join-linux.sh.j2 and common/sssd_sockets drift), records how they were, and the undo puts
them back with their failures cleared. Pure logic: systemctl is a fake that keeps each unit's state.
    python3 tests/setup/common/sssd_sockets_test.py"""
import os
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.common.sssd_sockets as ss  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


class Out:
    def __init__(self, stdout=""):
        self.stdout, self.returncode = stdout, 0


class Systemctl:
    """A fake systemctl: each unit's enablement and whether it is failed."""
    def __init__(self, units):
        self.units = dict(units)            # unit -> state
        self.failed = set(units)            # every socket failed at boot, as on the test Pi
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(args)
        verb, names = args[1], args[2:]
        if verb == "list-unit-files":
            return Out("".join(f"{u} {s} enabled\n" for u, s in sorted(self.units.items())))
        if verb == "is-enabled":
            return Out(self.units[names[0]] + "\n")
        names = [n for n in names if not n.startswith("--")]
        for n in names:
            if verb == "mask":
                self.units[n] = "masked"
            elif verb == "unmask":
                self.units[n] = "disabled"
            elif verb in ("enable", "preset"):
                self.units[n] = "enabled"
            elif verb == "disable":
                self.units[n] = "disabled"
            elif verb == "reset-failed":
                self.failed.discard(n)
        return Out()


DEFAULT = {"sssd-nss.socket": "enabled", "sssd-pam.socket": "enabled", "sssd-sudo.socket": "enabled",
           "sssd-pac.socket": "enabled", "sssd-autofs.socket": "disabled"}

sc = Systemctl(DEFAULT)
before = ss.socket_states(sc)
check("the states are read before fabric changes them", before == DEFAULT, before)
check("negative: a host whose sockets are as the packages left them is not masked", not ss.sockets_masked(sc))
masked = ss.mask_sockets(sc)
check("every sssd socket unit stopped, disabled, masked and its failure cleared",
      masked == sorted(DEFAULT) and all(s == "masked" for s in sc.units.values()) and not sc.failed
      and ["systemctl", "disable", "--now", *sorted(DEFAULT)] in sc.calls, (sc.units, sc.failed))
check("…so the join sees nothing left to change (idempotent)", ss.sockets_masked(sc))
sc.failed = set(DEFAULT)
lines = ss.restore_sockets(before, sc)
check("the undo puts each back as it was (enabled ones enabled, a disabled one disabled), failures cleared",
      sc.units == DEFAULT and not sc.failed and len(lines) == 1 and "sssd-autofs.socket disabled" in lines[0], (sc.units, lines))

sc = Systemctl({**DEFAULT, "sssd-ssh.socket": "enabled"})
ss.mask_sockets(sc)
lines = ss.restore_sockets({}, sc)
check("a socket fabric has no record of (its package came with fabric) goes back to its package's default",
      all(["systemctl", "preset", u] in sc.calls for u in sc.units) and "package's default" in lines[0], sc.calls)
lines = ss.restore_sockets(None, Systemctl({}))
check("negative: no sssd installed: nothing to put back", lines == [], lines)
check("negative: no systemctl at all is no units", ss.socket_units(lambda *a, **k: (_ for _ in ()).throw(OSError())) == [])

# one approach for both joins: the Linux join's script lists the same glob and disables and masks the same way
script = open(os.path.join(REPO, "templates", "nginx", "www", "certs", "join-linux.sh.j2")).read()
check(f"join-linux.sh.j2 finds the sockets with the same glob ({ss.GLOB})",
      f"systemctl list-unit-files '{ss.GLOB}' --no-legend" in script, ss.GLOB)
check("…and disables (--now) and masks them, as mask_sockets does",
      'systemctl disable --now "${sockets[@]}"' in script and 'systemctl mask "${sockets[@]}"' in script)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
