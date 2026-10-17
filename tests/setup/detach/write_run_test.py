"""write_run (manual 1.3.2.3.3): the run record saved atomically, 0600.
    python3 tests/setup/detach/write_run_test.py"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.read_run import read_run  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


with tempfile.TemporaryDirectory() as d:
    config = os.path.join(d, "config")
    rec = {"id": "r1", "state": "running", "done": ["preflight"], "restart_services": ["bind9"]}
    path = write_run(config, rec)
    check("the config folder is made when missing and the record round-trips", read_run(config) == rec,
          read_run(config))
    check("the record is 0600", stat.S_IMODE(os.stat(path).st_mode) == 0o600, oct(os.stat(path).st_mode))
    os.chmod(path, 0o644)
    write_run(config, {**rec, "state": "done"})
    check("…and stays 0600 when rewritten over a looser file", stat.S_IMODE(os.stat(path).st_mode) == 0o600)
    check("no temporary file is left beside it", os.listdir(config) == ["setup-run.yaml"], os.listdir(config))
    try:
        write_run(config, {"id": "r2", "bad": object()})
        check("negative: a value YAML cannot write is refused", False)
    except Exception:
        check("negative: a value YAML cannot write is refused, the old record kept whole and no temporary file left",
              read_run(config)["state"] == "done" and os.listdir(config) == ["setup-run.yaml"], os.listdir(config))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
