"""run_uninstall_command (manual 1.6.11.8, 2.3.1.32): with an export, the host's own computer account is removed
before the export stops the stack it needs (OpenBao and the DC), and uninstall does not try it again; without an
export, uninstall removes it itself; a refused command removes nothing.
    python3 tests/setup/run_uninstall_command_test.py"""
import contextlib
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.run_uninstall_command as ruc  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


calls = []
ruc.check_export_dir = lambda ctx, d: d
ruc.export_install = lambda ctx, d: calls.append(("export", d))
ruc.remove_host_account = lambda cfg, v, secrets: calls.append(("account",)) or ["the domain: account FAB1$ removed"]
ruc.uninstall = lambda ctx, host_account=True: calls.append(("uninstall", host_account))
ruc._package_installed = lambda: False
tmp = tempfile.mkdtemp()


def run(args):
    calls.clear()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = ruc.run_uninstall_command(args, tmp)
    return rc, out.getvalue() + err.getvalue()


rc, out = run(["--yes", "--export", "/var/backups/x"])
check("with an export: the host's account goes first, then the export, then uninstall without the account",
      rc == 0 and calls == [("account",), ("export", "/var/backups/x"), ("uninstall", False)], (rc, calls, out))
check("…and what was done with the account is said", "account FAB1$ removed" in out, out)

rc, out = run(["--yes", "--no-export"])
check("without an export: uninstall removes the account itself (the stack still runs)",
      rc == 0 and calls == [("uninstall", True)], (rc, calls, out))

rc, out = run(["--yes"])
check("refused (--yes without an export choice): says why and removes nothing, not even the account",
      rc == 1 and calls == [] and "choose --export DIR or --no-export" in out, (rc, calls, out))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
