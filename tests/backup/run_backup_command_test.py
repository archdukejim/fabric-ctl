#!/usr/bin/env python3
"""`fabricctl backup …` (backup/run_backup_command, read_backup_key, backup_lock; manual 1.3.7.11): the routing, the
key never taken from a command line value, and one backup at a time. make_backup and the schedule stood in for; the
bundle itself is bundle_test.py's, the real run the host suite's.

    python3 tests/backup/run_backup_command_test.py
"""
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.read_backup_key as rbk  # noqa: E402
import fabriclib.backup.run_backup_command as rbc  # noqa: E402
from fabriclib.backup.backup_lock import backup_lock  # noqa: E402
from fabriclib.backup.backup_running import backup_running  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
KEY = "age1" + "q" * 58
PRIVATE = "AGE-SECRET-KEY-1" + "Q" * 58


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


made, answers = [], []


def fake_make(base, v, secrets_file, kind, method, **kw):
    made.append((kind, method, kw))
    return "/x.fabric.tar"


rbc.make_backup = fake_make
rbc.prune_bundles = lambda keep: ["old.fabric.tar"]
rbk.ask_secret = lambda qid, prompt: answers.pop(0)
V = {"hostname": "h", "backup_public_key": KEY, "backup_keep": 7}


def run(args, v=V, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    real = sys.stdout, sys.stderr, sys.stdin
    sys.stdout, sys.stderr, sys.stdin = out, err, io.StringIO(stdin)
    try:
        code = rbc.run_backup_command("/opt/fabric", v, "/opt/fabric/config/fabric-secrets.yml", args)
    finally:
        sys.stdout, sys.stderr, sys.stdin = real
    return code, out.getvalue() + err.getvalue()


answers[:] = ["a long passphrase", "a long passphrase"]
code, out = run([])
# covers: cli:backup ask:backup.passphrase ask:backup.passphrase_again +
check("positive: a bundle by hand asks the passphrase twice, online, kind manual",
      code == 0 and made[-1] == ("manual", "online", {"passphrase": "a long passphrase", "public_key": None}),
      (code, out, made))
answers[:] = ["a long passphrase", "another one, longer"]
code, out = run([])
# covers: cli:backup ask:backup.passphrase_again -
check("negative: two passphrases that differ: refused, nothing made", code == 1 and "differ" in out and len(made) == 1,
      (code, out))
answers[:] = ["short", "short"]
code, out = run([])
# covers: ask:backup.passphrase -
check("negative: a passphrase under 12 characters: refused", code == 1 and "shorter than 12" in out, (code, out))
code, out = run(["--public-key", KEY])
check("positive: to a public key: no passphrase asked",
      code == 0 and made[-1][2] == {"passphrase": None, "public_key": KEY}, made[-1])
code, out = run(["--scheduled"])
check("positive: the timer's run: the schedule's key, kind scheduled, then the old ones pruned",
      code == 0 and made[-1][:2] == ("scheduled", "online") and made[-1][2]["public_key"] == KEY
      and "old.fabric.tar" in out, (code, out, made[-1]))
code, out = run(["--scheduled"], v={"hostname": "h"})
check("negative: --scheduled with no schedule's key is refused", code == 1 and "no schedule" in out, (code, out))
code, out = run(["--key-stdin"], stdin="a passphrase from stdin\n")
check("positive: --key-stdin reads the passphrase from standard input, never an argument",
      code == 0 and made[-1][2]["passphrase"] == "a passphrase from stdin", made[-1])
code, out = run(["--public-key"])
check("negative: --public-key without a value is refused", code == 1 and "needs a value" in out, (code, out))

rbc.list_bundles = lambda: [{"file": "f.fabric.tar", "size": 3 << 20, "fabric_version": "0.10.1",
                             "sections": ["dns", "pki"], "error": None}]
code, out = run(["list"])
# covers: cli:backup.list +
check("positive: list prints each bundle with its size, version and sections",
      code == 0 and "f.fabric.tar  3 MiB  fabric 0.10.1  dns, pki" in out, out)
rbc.list_bundles = lambda: []
code, out = run(["list"])
# covers: cli:backup.list -
check("negative: no bundles: says so", code == 0 and "no bundles" in out, out)

rbc.check_bundle = lambda path: {"host": "h", "made": "2026-11-19T03:00:00Z", "fabric_version": "0.10.1",
                                 "kind": "scheduled", "method": "online", "opened_by": KEY}
code, out = run(["check", "/var/backups/fabric/f.fabric.tar"])
# covers: cli:backup.check +
check("positive: check says a whole bundle is whole, and what opens it", code == 0 and "whole:" in out and KEY in out,
      out)


def broken(path):
    raise ValidationError(f"{path}: section dns has changed since the bundle was made")


rbc.check_bundle = broken
code, out = run(["check", "/x.fabric.tar"])
# covers: cli:backup.check -
check("negative: check refuses a changed bundle, naming the section", code == 1 and "section dns" in out, out)
code, out = run(["check"])
check("negative: check with no file prints the usage", code == 2 and "usage:" in out, out)

sched = []


def fake_schedule(actor, **kw):
    sched.append(kw)
    return {"schedule": "on 02:00", "keep": 5, "public_key": KEY}


rbc.set_backup_schedule = fake_schedule
code, out = run(["schedule", "--time", "02:00", "--keep", "5", "--public-key", KEY])
# covers: cli:backup.schedule +
check("positive: schedule passes the time, keep and key",
      code == 0 and sched[-1] == {"time": "02:00", "keep": 5, "public_key": KEY, "off": False} and "on 02:00" in out,
      (sched, out))
code, out = run(["schedule", "--keep", "many"])
# covers: cli:backup.schedule -
check("negative: schedule with a keep that is not a number is refused", code == 1 and "--keep" in out, out)
code, out = run(["nonsense"])
check("negative: an unknown subcommand prints the usage", code == 2 and "usage:" in out, out)

tmp = tempfile.mkdtemp()
lock = os.path.join(tmp, "backup.lock")
check("positive: no lock file: no backup running", backup_running(lock) is None)
with backup_lock(path=lock):
    check("positive: while one holds the lock, it is seen as running", backup_running(lock) == str(os.getpid()))
    pid = os.fork()
    if pid == 0:                                  # a second process: refused
        try:
            with backup_lock("a restore", path=lock):
                os._exit(0)
        except ValidationError as exc:
            os._exit(3 if "a restore cannot start" in str(exc) else 4)
    _, status = os.waitpid(pid, 0)
    check("negative: a second backup or restore is refused while one runs", os.waitstatus_to_exitcode(status) == 3,
          status)
check("positive: the lock is free again once the block ends", backup_running(lock) is None)

key_file = os.path.join(tmp, "key")
with open(key_file, "w") as f:
    f.write("# created\n" + PRIVATE + "\n")
os.chmod(key_file, 0o600)
check("positive: a private key read from a root-only file",
      rbk.read_backup_key(["--key-file", key_file], {}, opening=True)["private_key"] == PRIVATE)
os.chmod(key_file, 0o644)
try:
    rbk.read_backup_key(["--key-file", key_file], {}, opening=True)
    check("negative: a key file others can read is refused", False)
except ValidationError as exc:
    check("negative: a key file others can read is refused", "chmod 600" in str(exc), exc)
answers[:] = [PRIVATE]
got = rbk.read_backup_key([], {}, opening=True)
# covers: ask:backup.open_key +
check("positive: a private key typed at the prompt is taken as one", got == {"passphrase": None,
      "private_key": PRIVATE}, got)
answers[:] = [""]
got = rbk.read_backup_key([], {}, opening=True)
# covers: ask:backup.open_key -
check("negative: an empty answer is a passphrase that age then refuses, never a key",
      got == {"passphrase": "", "private_key": None}, got)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
