"""save_vars (1.17): atomic, the old file's mode kept, a failed write leaves the old file whole.
    python3 tests/common/save_vars_test.py"""
import os
import stat
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import yaml  # noqa: E402

from fabriclib.common.save_vars import save_vars  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


with tempfile.TemporaryDirectory() as d:
    path = os.path.join(d, "vars.yaml")
    save_vars({"domain": "lan.test", "note": "", "big": ["x" * 64] * 2000}, path)
    data = yaml.safe_load(open(path))
    check("written: keys kept, an empty string saved as null", data["domain"] == "lan.test" and data["note"] is None)
    os.chmod(path, 0o600)
    save_vars({"domain": "lan.test", "big": ["y" * 64] * 2000}, path)
    check("the old file's mode is kept (0600)", stat.S_IMODE(os.stat(path).st_mode) == 0o600,
          oct(os.stat(path).st_mode))
    check("no temporary file left behind", os.listdir(d) == ["vars.yaml"], os.listdir(d))

    seen, stop = [], threading.Event()

    def reader():
        while not stop.is_set():
            seen.append(yaml.safe_load(open(path)))

    t = threading.Thread(target=reader)
    t.start()
    for i in range(40):
        save_vars({"domain": "lan.test", "i": i, "big": ["z" * 64] * 2000}, path)
    stop.set()
    t.join()
    check("a reader without the lock never sees an empty or partial file (40 writes)",
          seen and all(isinstance(s, dict) and len(s.get("big", [])) == 2000 for s in seen), len(seen))

    before = open(path).read()

    import fabriclib.common.save_vars as sv
    real = sv.yaml.dump

    def half(data, f, **kw):         # the disk fills mid-write: part of the file, then an error
        f.write("domain: lan.te")
        raise OSError(28, "No space left on device")

    sv.yaml.dump = half
    try:
        save_vars({"domain": "lan.test"}, path)
        raised = False
    except OSError:
        raised = True
    finally:
        sv.yaml.dump = real
    check("negative: a write that fails half way (disk full) raises, and the old file stays whole; no temporary file",
          raised and open(path).read() == before and os.listdir(d) == ["vars.yaml"])

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
