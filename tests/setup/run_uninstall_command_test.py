"""run_uninstall_command (manual 1.3.7.13, 1.6.11.8, 2.3.1.32): with a backup bundle, its passphrase is asked before
anything is touched, the host's own computer account is removed before the cold bundle stops the stack it needs
(OpenBao and the DC), and uninstall does not try it again; without one, uninstall removes the account itself; 0.10.0's
--export and --no-export still work; a refused command removes nothing. make_backup and uninstall stood in for: the
bundle is tests/backup's, the real run the sandbox's.
    python3 tests/setup/run_uninstall_command_test.py"""
import contextlib
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.run_uninstall_command as ruc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

PASS = FAIL = 0
PASSPHRASE = "a passphrase for this test"


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


calls, answers = [], {}
made = {"fail": None}


def fake_make(base, v, secrets_file, kind, method, **key):
    calls.append(("bundle", kind, method, key.get("passphrase") or key.get("public_key")))
    if made["fail"]:
        raise ValidationError(made["fail"])
    return "/var/backups/fabric/fabric-1-20261119T000000Z-uninstall.fabric.tar"


ruc.make_backup = fake_make
ruc.remove_host_account = lambda cfg, v, secrets: calls.append(("account",)) or ["the domain: account FAB1$ removed"]
ruc.uninstall = lambda ctx, host_account=True: calls.append(("uninstall", host_account))
ruc._package_installed = lambda: False
ruc.ask = lambda qid, prompt, default=None: calls.append(("ask", qid)) or answers.get(qid, "")
tmp = tempfile.mkdtemp()


def run(args, stdin=PASSPHRASE + "\n"):
    calls.clear()
    out, err = io.StringIO(), io.StringIO()
    real, sys.stdin = sys.stdin, io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ruc.run_uninstall_command(args, tmp)
    finally:
        sys.stdin = real
    return rc, out.getvalue() + err.getvalue()


rc, out = run(["--yes", "--backup", "--key-stdin"])
# covers: cli:uninstall +
check("with a bundle: the host's account goes first, then the cold bundle (kind uninstall), then uninstall without "
      "the account", rc == 0 and calls == [("account",), ("bundle", "uninstall", "cold", PASSPHRASE),
                                           ("uninstall", False)], (rc, calls, out))
check("…what was done with the account is said, as done (a tick)", "account FAB1$ removed" in out and "✓" in out, out)
check("…and where the bundle is, with how to restore it",
      "fabricctl restore" in out and "-uninstall.fabric.tar" in out, out)

said = ["the domain: this host's computer account FAB1$ NOT removed (OpenBao is not reachable): remove it in the web "
        "console (Directory → Machines)"]
ruc.remove_host_account = lambda cfg, v, secrets: calls.append(("account",)) or said
rc, out = run(["--yes", "--backup", "--key-stdin"])
line = [x for x in out.splitlines() if "FAB1$" in x]
check("one the DC refused is a warning (!), not a tick, and the uninstall goes on",
      rc == 0 and line and "!" in line[0] and "✓" not in line[0] and calls[-1] == ("uninstall", False), (line, calls))

rc, out = run(["--yes", "--export", "/var/backups/x", "--key-stdin"])
check("0.10.0's --export DIR: a bundle instead, saying so (the folder is not used)",
      rc == 0 and ("bundle", "uninstall", "cold", PASSPHRASE) in calls and "--export is now --backup" in out,
      (rc, calls, out))

rc, out = run(["--yes", "--no-backup"])
check("without a bundle: uninstall removes the account itself (the stack still runs)",
      rc == 0 and calls == [("uninstall", True)], (rc, calls, out))
rc, out = run(["--yes", "--no-export"])
check("0.10.0's --no-export is --no-backup", rc == 0 and calls == [("uninstall", True)], (rc, calls, out))

rc, out = run(["--yes"])
# covers: cli:uninstall -
check("refused (--yes without a backup choice): says why and removes nothing, not even the account",
      rc == 1 and calls == [] and "choose --backup or --no-backup" in out, (rc, calls, out))
rc, out = run(["--yes", "--backup", "--key-stdin"], stdin="short\n")
check("negative: a passphrase shorter than 12 characters: refused before anything is touched",
      rc == 1 and calls == [] and "shorter than 12" in out, (rc, calls, out))
made["fail"] = "too little room in /var/backups/fabric"
rc, out = run(["--yes", "--backup", "--key-stdin"])
made["fail"] = None
check("negative: the bundle not made: fabric is not removed, and how to start it again is said",
      rc == 1 and ("uninstall", False) not in calls and "not removed" in out and "fabricctl start" in out,
      (rc, calls, out))

# interactive: the bundle offered by default, its passphrase asked before the last confirmation
answers.update({"uninstall.backup": "", "uninstall.confirm": "no"})
rc, out = run(["--key-stdin"])
# covers: ask:uninstall.backup +
# covers: ask:uninstall.confirm -
check("interactive, not confirmed: nothing removed and no bundle made", rc == 1 and not any(
    c[0] in ("bundle", "uninstall", "account") for c in calls) and "nothing changed" in out, (rc, calls, out))
answers.update({"uninstall.backup": "n", "uninstall.confirm": "yes"})
rc, out = run([])
# covers: ask:uninstall.backup -
# covers: ask:uninstall.confirm +
check("interactive, no bundle, confirmed: removed, no passphrase asked", rc == 0 and calls[-1] == ("uninstall", True)
      and not any(c[0] == "bundle" for c in calls), (rc, calls, out))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
