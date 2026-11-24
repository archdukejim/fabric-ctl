#!/usr/bin/env python3
"""Restore from a backup's run in fabric-setup.service (setup/detach/run_restore, manual 1.3.7.10): the bundle restored
with the handed-over key and the changes, then setup run on it unattended with every step; what moved kept for the
finish; a refused restore ends the run failed with nothing run after it; a unit restarted after the unpack does not
unpack again; Proceed's allow-again becomes setup's --approve with the groups allowed before, never one declined.
restore_bundle and setup are stood in for (the real restore: tests/backup/restore_test.py).

    python3 tests/setup/detach/run_restore_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.setup.detach.run_restore as rr  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
STEPS = [("prereqs", None, ""), ("deploy", None, ""), ("dc", None, "")]


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Ctx:
    deploy_base, source_dir, config_dir = "/opt/fabric", "/opt/fabric/fabric", tempfile.mkdtemp()


class Done:
    def __init__(self, rc):
        self.returncode = rc


rr.read_build = lambda d: {"version": "0.10.1"}
rr.load_consent = lambda d: {"firewall": {"answer": "yes"}, "ports": {"answer": "yes"}, "member": {"answer": "no"}}


def go(options, key={"passphrase": "p" * 12, "private_key": None}, refuse=None, rc=0, record=None):
    calls, saved = [], []

    def restore(base, path, k, changes, version, actor, source):
        calls.append(("restore", path, k, changes, version, actor, source))
        if refuse:
            raise ValidationError(refuse)
        return {"changed": {"host_ip": ("10.0.0.5", "10.20.0.5")}, "leftover": [("dns.lab.test.A.far", "10.0.0.9")]}

    def run(cmd):
        calls.append(("setup", cmd))
        return Done(rc)

    record = record or {"id": "r1", "state": "running", "options": {"restore": options}}
    out = rr.run_restore(Ctx(), record, lambda r: saved.append(dict(r)), key, STEPS, restore=restore, run=run,
                         cli="/x/cli.py")
    return out, record, calls, saved


MOVE = {"bundle": "/var/backups/fabric/b.fabric.tar", "changes": {"host_ip": "10.20.0.5"}, "allow_again": True}
out, record, calls, saved = go(MOVE)
setup = calls[1][1]
check("restored first, with the key, the changes and who, then setup on it", out == 0 and calls[0] == (
    "restore", MOVE["bundle"], {"passphrase": "p" * 12, "private_key": None}, {"host_ip": "10.20.0.5"}, "0.10.1",
    "setup site", "web") and calls[1][0] == "setup", calls)
check("setup runs unattended with every step, here, not as another run", setup[2:5] == ["setup", "--yes",
      "--non-interactive"] and setup.count("--step") == 3 and "--worker" not in setup, setup)
check("allow again: --approve with the groups allowed before, never the one declined",
      setup[setup.index("--approve") + 1] == "firewall,ports", setup)
check("the record ends done, what moved kept for the finish", record["state"] == "done" and record["result"] == 0
      and record["restored"] == {"changed": {"host_ip": ["10.0.0.5", "10.20.0.5"]},
                                 "leftover": [["dns.lab.test.A.far", "10.0.0.9"]]}, record)
check("what moved is saved before setup starts (a restart finds it)", saved and saved[0].get("restored"), saved)
check("the key is in no record saved", all("p" * 12 not in str(r) for r in saved), saved)

out, record, calls, _ = go(dict(MOVE, allow_again=False, changes={}))
check("nothing moving: no --approve, the recorded answers stand", "--approve" not in calls[1][1], calls[1][1])
out, record, calls, _ = go(MOVE, rc=1)
check("negative: setup fails on the restored bundle: the run ends failed", out == 1 and record["state"] == "failed"
      and record["result"] == 1, record)
out, record, calls, saved = go(MOVE, refuse="the bundle's key does not open it")
check("negative: the restore refused (a wrong key): failed, setup never run", out == 1 and len(calls) == 1
      and record["state"] == "failed" and "restored" not in record, (calls, record))
again = {"id": "r1", "state": "running", "options": {"restore": MOVE},
         "restored": {"changed": {}, "leftover": []}}
out, record, calls, _ = go(MOVE, key=None, record=again)
check("a unit restarted after the unpack: not unpacked again (the key is gone), setup runs again",
      out == 0 and [c[0] for c in calls] == ["setup"], calls)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
