#!/usr/bin/env python3
"""fabric-agent's backup changes (agent/post_backup; manual 1.3.7.9, 1.3.7.12), their logic with the work stood in for:
every route refuses someone who is not a Domain Admin before anything else; Back up now and a section restore start a
job whose result never holds the key; the refusals (a short passphrase, no schedule's key, secrets alone, an unknown
section, the site's name not typed, a backup running, a bad keep) start nothing. The real routes on a running install:
tests/sandbox/run.sh; the Domain Admins check in a real DC: tests/samba/grants.py.

    python3 tests/agent/post_backup_test.py
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import agent.backup_file as bf  # noqa: E402
import agent.post_backup as pb  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
FOLDER = tempfile.mkdtemp()
NAME = "fabric-fabric-20261122T030000Z-manual.fabric.tar"
open(os.path.join(FOLDER, NAME), "wb").close()
bf.FOLDER = FOLDER
bf.backup_file.__defaults__ = (FOLDER,)
V = {"deploy_base_dir": FOLDER, "site_name": "lan", "backup_public_key": ""}


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


class Jobs:
    def __init__(self):
        self.started = []

    def start(self, kind, owner, fn):
        self.started.append((kind, owner, fn()))
        return {"id": "j1"}


calls = []
pb.backup_running = lambda: running
pb.read_build = lambda d: {"version": "0.10.1"}


def call(route, data, admin=True, v=V):
    jobs, audits = Jobs(), []
    calls.clear()
    try:
        out = pb.post_backup(["backup", route], "dana", data, "dana", load=lambda: dict(v),
                             allowed=lambda vv, c: admin, jobs=jobs, audit=lambda *a, **k: audits.append(a),
                             make=lambda *a, **k: calls.append(("make", k)) or os.path.join(FOLDER, NAME),
                             restore=lambda *a, **k: calls.append(("restore", a)) or {"safety": "/x/safe.tar"},
                             schedule=lambda *a, **k: calls.append(("schedule", k)) or {"schedule": "off"})
        return out, None, jobs, audits
    except ValidationError as exc:
        return None, str(exc), jobs, audits


running = None
for route, data in (("now", {"passphrase": "twelve-chars-1"}), ("schedule", {"off": True}),
                    ("restore", {"file": NAME, "section": "dns", "key": "k" * 12, "confirm": "lan"})):
    out, err, jobs, audits = call(route, data, admin=False)
    check(f"{route}: not a Domain Admin: refused first, nothing started, audited or changed",
          "Domain Admins" in (err or "") and not jobs.started and not audits and not calls, (err, calls))

out, err, jobs, audits = call("now", {"passphrase": "twelve-chars-1"})
check("Back up now: a job, the bundle named in its result, the passphrase only in the call, audited at its start",
      out == {"id": "j1"} and "Bundle made" in jobs.started[0][2]["message"]
      and "twelve-chars-1" not in str(jobs.started[0][2]) and calls[0][1]["passphrase"] == "twelve-chars-1"
      and audits[0][1] == "BACKUP_START", (out, jobs.started, audits))
out, err, jobs, _ = call("now", {"passphrase": "short"})
check("negative: a passphrase under 12 characters: refused, no job", "12 characters" in (err or "")
      and not jobs.started, err)
out, err, jobs, _ = call("now", {"scheduled_key": True})
check("negative: the schedule's key with no schedule: refused", "no schedule's public key" in (err or ""), err)
out, err, jobs, _ = call("now", {"scheduled_key": True}, v=dict(V, backup_public_key="age1abc"))
check("the schedule's key when it is set: made to it", calls and calls[0][1]["public_key"] == "age1abc", calls)
running = "4242"
out, err, jobs, _ = call("now", {"passphrase": "twelve-chars-1"})
check("negative: a backup running: refused, naming it, no job", "pid 4242" in (err or "") and not jobs.started, err)
running = None

ok = {"file": NAME, "section": "dns", "key": "AGE-SECRET-KEY-1ABC", "confirm": "lan"}
out, err, jobs, audits = call("restore", ok)
check("a section restore: a job naming the section, the bundle and the safety bundle; the private key not in it",
      out == {"id": "j1"} and "dns restored from " + NAME in jobs.started[0][2]["message"]
      and "safe.tar" in jobs.started[0][2]["message"] and "AGE-SECRET" not in str(jobs.started[0][2])
      and calls[0][1][4] == {"passphrase": None, "private_key": "AGE-SECRET-KEY-1ABC"}
      and audits[0][1] == "RESTORE_SECTION_START", (jobs.started, calls))
for name, data, words in (("secrets alone", dict(ok, section="secrets"), "only with the whole bundle"),
                          ("an unknown section", dict(ok, section="nope"), "section: one of"),
                          ("the site's name not typed", dict(ok, confirm="LAN "), "type the site's name (lan)"),
                          ("no key", dict(ok, key=""), "key:"),
                          ("a path instead of a bundle", dict(ok, file="../../etc/shadow"), "the name of a bundle"),
                          ("a bundle not there", dict(ok, file="fabric-x-20990101T000000Z-manual.fabric.tar"),
                           "no bundle")):
    out, err, jobs, _ = call("restore", data)
    check(f"negative: {name}: refused, no job", words in (err or "") and not jobs.started and not calls, err)

out, err, _, _ = call("schedule", {"time": "04:15", "keep": "3", "public_key": "age1abc"})
check("the schedule: passed on as set_backup_schedule takes it",
      calls[0][1] == {"time": "04:15", "keep": 3, "public_key": "age1abc", "off": False, "source": "web"}, calls)
out, err, _, _ = call("schedule", {"keep": "many"})
check("negative: keep that is not a number: refused, nothing saved", "keep:" in (err or "") and not calls, err)
print("--- the whole bundle (reinstall)")
started = []


def call_whole(data, admin=True, refuse=None, start_refuse=None):
    audits = []
    started.clear()

    def whole(base, path, key, version):
        started.append(("checked", key))
        if refuse:
            raise ValidationError(refuse)

    def start(path, key, actor):
        if start_refuse:
            raise ValidationError(start_refuse)
        started.append(("started", os.path.basename(path), key, actor))
        return {"unit": "fabric-console-restore", "log": "/x"}

    try:
        out = pb.post_backup(["backup", "reinstall"], "dana", data, "dana", load=lambda: dict(V),
                             allowed=lambda vv, c: admin, audit=lambda *a, **k: audits.append(a), whole=whole,
                             start=start)
        return out, None, audits
    except ValidationError as exc:
        return None, str(exc), audits


ok = {"file": NAME, "key": "a passphrase 12", "confirm": "lan"}
out, err, audits = call_whole(ok)
# covers: agent:post.backup.reinstall +
check("checked, then started as its own unit by the person, audited at its start; the key only passed on",
      out == {"started": True, "unit": "fabric-console-restore"} and [s[0] for s in started] == ["checked", "started"]
      and started[1] == ("started", NAME, {"passphrase": "a passphrase 12", "private_key": None}, "dana")
      and audits[0][1] == "RESTORE_WHOLE_START" and "a passphrase 12" not in str(audits), (out, err, started))
# covers: agent:post.backup.reinstall -
for name, kw, words in (("not a Domain Admin", {"admin": False}, "Domain Admins"),
                        ("the site's name not typed", {"data": dict(ok, confirm="x")}, "type the site's name"),
                        ("no key", {"data": dict(ok, key="")}, "key:"),
                        ("a bundle the check refuses", {"refuse": "made by fabric 0.11.0, newer"}, "newer"),
                        ("one already running", {"start_refuse": "a whole restore from the console is running"},
                         "running")):
    out, err, audits = call_whole(kw.pop("data", ok), **kw)
    check(f"negative: {name}: refused, nothing started or audited", words in (err or "")
          and not any(s[0] == "started" for s in started) and not audits, (err, started))
running = "77"
out, err, audits = call_whole(ok)
running = None
check("negative: a backup or restore running: refused before the bundle is even checked", "pid 77" in (err or "")
      and not started, (err, started))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
