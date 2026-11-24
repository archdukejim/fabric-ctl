#!/usr/bin/env python3
"""One bundle of the install (backup/make_backup; manual 1.3.7.4, 1.3.7.6): fabric's own secrets read out of OpenBao and
packed in the secrets section for an online bundle as for a cold one (a restore's setup needs them before OpenBao runs:
found by the sandbox, 2026-11-23), beside the online vault snapshot; never for a safety bundle of another section;
fabric stopped only for a cold one; the RAM folder gone after. The lock, the dumps, the packing and the audit are stood
in for (real bundles: tests/backup/bundle_test.py, the sandbox's Back up now).

    python3 tests/backup/make_backup_test.py
"""
import os
import sys
import tempfile
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.make_backup as mb  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


tmp = tempfile.mkdtemp()
mb.DUMPS = os.path.join(tmp, "dumps")
events, packed = [], {}


@contextmanager
def lock(what):
    yield


mb.backup_lock = lock
mb.check_backup_space = lambda folder, paths: None
mb.write_audit = lambda *a, **k: None
mb.ok = mb.info = lambda *a, **k: None
mb.secrets_in_openbao = lambda path: True
mb.export_secrets = lambda path, dest: (events.append("export"), os.makedirs(os.path.dirname(dest), exist_ok=True),
                                        open(dest, "w").write("fabric's secrets"))
mb.stop_for_copy = lambda base: events.append("stop")


def plan(base, v, method, only=None):
    folder = os.path.join(mb.DUMPS, "secrets")
    if method == "online" and (only is None or "secrets" in only):
        os.makedirs(folder, exist_ok=True)
        open(os.path.join(folder, "openbao.snap"), "w").write("snapshot")
        return [("secrets", [], folder, None)]
    return [("secrets", [], None, None), ("dns", [], None, None)]


def bundle(plan_, host, meta, kind, passphrase=None, public_key=None, folder=None):
    extra = dict((s, x) for s, _, x, _ in plan_).get("secrets")
    packed["secrets"] = sorted(os.listdir(extra)) if extra else []
    path = os.path.join(tmp, f"fabric-{host}-20261123T000000Z-{kind}.fabric.tar")
    open(path, "w").close()
    return path


mb.backup_plan, mb.make_bundle = plan, bundle
for method in ("online", "cold"):
    events.clear()
    mb.make_backup(tmp, {"hostname": "fabric-1"}, "/x/fabric-secrets.yml", "manual", method, passphrase="p" * 12)
    check(f"{method}: fabric's secrets exported and packed in the secrets section"
          + (", beside the vault's snapshot" if method == "online" else ", fabric stopped after"),
          "export" in events and "fabric-secrets.yml" in packed["secrets"]
          and (("openbao.snap" in packed["secrets"] and "stop" not in events) if method == "online"
               else events == ["export", "stop"]), (events, packed))
    check(f"{method}: the RAM folder is gone after", not os.path.exists(mb.DUMPS))
events.clear()
mb.make_backup(tmp, {"hostname": "fabric-1"}, "/x/fabric-secrets.yml", "manual", "online", passphrase="p" * 12,
               only={"dns"})
check("negative: a safety bundle of another section (dns): fabric's secrets not read out at all",
      "export" not in events and packed["secrets"] == [], (events, packed))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
