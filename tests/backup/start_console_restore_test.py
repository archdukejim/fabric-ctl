#!/usr/bin/env python3
"""The console's whole restore started (backup/start_console_restore, backup/check_whole_restore; manual 1.3.7.9):
`fabricctl reinstall --from` as its own systemd unit, the key in a root-only file and never on its command line, refused
while one runs, the key file removed when systemd-run refuses; and the checks made before anything is stopped (a newer
bundle, another install root, another address, a wrong key). systemd and the bundle stood in for: the real run is
tests/sandbox/run.sh's.

    python3 tests/backup/start_console_restore_test.py
"""
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.check_whole_restore as cwr  # noqa: E402
from fabriclib.backup.start_console_restore import start_console_restore  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
tmp = tempfile.mkdtemp()
KEY_FILE = os.path.join(tmp, "run", "console-restore.key")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def systemd(active=False, refuse=False):
    seen = []

    def run(cmd, **kw):
        seen.append(cmd)
        if cmd[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(cmd, 0 if active else 3, b"", b"")
        if cmd[0] == "systemd-run":
            seen.append(("key file", open(KEY_FILE).read() if os.path.exists(KEY_FILE) else None,
                         oct(os.stat(KEY_FILE).st_mode & 0o777) if os.path.exists(KEY_FILE) else None))
            return subprocess.CompletedProcess(cmd, 1 if refuse else 0, "", "Unit already exists" if refuse else "")
        raise AssertionError(cmd)
    return run, seen


run, seen = systemd()
out = start_console_restore("/var/backups/fabric/b.fabric.tar", {"passphrase": "secret words here",
                                                                 "private_key": None}, "dana", run=run,
                            key_file=KEY_FILE, log=os.path.join(tmp, "console-restore.log"))
cmd = next(c for c in seen if isinstance(c, list) and c[0] == "systemd-run")
key_seen = next(c for c in seen if isinstance(c, tuple))
check("started as the unit fabric-console-restore: reinstall --from the bundle, --key-file-once, the person named, its "
      "output to the log", out["unit"] == "fabric-console-restore" and "--unit=fabric-console-restore" in cmd
      and cmd[cmd.index("reinstall"):cmd.index("reinstall") + 3] == ["reinstall", "--from",
                                                                     "/var/backups/fabric/b.fabric.tar"]
      and "--key-file-once" in cmd and "--setenv=FABRIC_ACTOR=dana" in cmd
      and any(c.startswith("--property=StandardOutput=append:") for c in cmd), cmd)
check("the key is in the root-only file when the unit starts, never on its command line",
      key_seen[1] == "secret words here\n" and (os.name == "nt" or key_seen[2] == "0o600")
      and not any("secret words" in str(c) for c in cmd), key_seen)
run, seen = systemd(active=True)
try:
    start_console_restore("/b", {"passphrase": "p"}, "dana", run=run, key_file=KEY_FILE)
    check("negative: one already running: refused, nothing started", False)
except ValidationError as exc:
    check("negative: one already running: refused, nothing started", "running already" in str(exc)
          and not any(isinstance(c, list) and c[0] == "systemd-run" for c in seen), exc)
if os.path.exists(KEY_FILE):
    os.remove(KEY_FILE)
run, seen = systemd(refuse=True)
try:
    start_console_restore("/b", {"passphrase": "p"}, "dana", run=run, key_file=KEY_FILE)
    check("negative: systemd-run refuses: said, the key file removed again", False)
except ValidationError as exc:
    check("negative: systemd-run refuses: said, the key file removed again", "could not start" in str(exc)
          and not os.path.exists(KEY_FILE), exc)

print("--- what is checked before anything is stopped")
MANIFEST = {"fabric_version": "0.10.1", "base": "/opt", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
            "lan_gateway": "10.0.0.1"}


def whole(manifest=None, version="0.10.1", problem="", wrong_key=False):
    cwr.check_bundle = lambda path: dict(MANIFEST, **(manifest or {}))

    def opens(path, **key):
        if wrong_key:
            raise ValidationError("the passphrase does not open this bundle")
    try:
        return cwr.check_whole_restore("/opt", "/b", {"passphrase": "p"}, version, problem=lambda a: problem,
                                       opens=opens), None
    except ValidationError as exc:
        return None, str(exc)


check("a bundle of this fabric, this root and this host's addresses, the key right: its manifest",
      whole()[0] == MANIFEST)
check("an older bundle (setup migrates it): accepted", whole(version="0.10.2")[0] is not None)
for name, kw, words in (("made by a newer fabric", {"manifest": {"fabric_version": "0.11.0"}}, "newer than this"),
                        ("of another install root", {"manifest": {"base": "/srv"}}, "not /opt"),
                        ("of an address this host does not have", {"problem": "10.0.0.5 is not on this host"},
                         "4.2.4.8"),
                        ("a wrong key", {"wrong_key": True}, "does not open")):
    check(f"negative: {name}: refused", words in (whole(**kw)[1] or ""), whole(**kw))
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
