"""run_reinstall_command (manual 1.3.7.7, 1.3.7.13): the changes and the passphrase checked before anything is stopped,
then a cold bundle (kind reinstall), uninstall (the host's account kept: the restored directory still holds it), the
bundle restored whole with the changes, and setup run; a restore that fails names the bundle. make_backup, uninstall,
restore_bundle and setup's exec stood in for: the bundle is tests/backup's, the real run the sandbox's.
    python3 tests/setup/run_reinstall_command_test.py"""
import contextlib
import io
import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.run_reinstall_command as rrc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
PASSPHRASE = "a passphrase for this test"
BUNDLE = "/var/backups/fabric/fabric-1-20261119T000000Z-reinstall.fabric.tar"


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


calls = []
restore = {"fail": None}


def fake_restore(base, path, key, changes, package_version):
    calls.append(("restore", path, key["passphrase"], changes))
    if restore["fail"]:
        raise ValidationError(restore["fail"])


rrc.make_backup = lambda base, v, sf, kind, method, **key: calls.append(("bundle", kind, method,
                                                                        key["passphrase"])) or BUNDLE
rrc.uninstall = lambda ctx, host_account=True: calls.append(("uninstall", host_account))
rrc.restore_bundle = fake_restore
rrc.stage_source = lambda ctx: "/var/tmp/fabric-reinstall-src/fabric"
rrc.os.execv = lambda exe, argv: calls.append(("setup", argv[2:]))
rrc.ask = lambda qid, prompt, default=None: answer["v"]
answer = {"v": "yes"}
tmp = tempfile.mkdtemp()
os.makedirs(os.path.join(tmp, "fabric", "config"))
with open(os.path.join(tmp, "fabric", "config", "vars.yaml"), "w") as f:
    yaml.safe_dump({"hostname": "fabric-1", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
                    "lan_gateway": "10.0.0.1"}, f)


def run(args, stdin=PASSPHRASE + "\n", base=tmp):
    calls.clear()
    out = io.StringIO()
    real, sys.stdin = sys.stdin, io.StringIO(stdin)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = rrc.run_reinstall_command(args, base)
    finally:
        sys.stdin = real
    return rc, out.getvalue()


rc, out = run(["--key-stdin", "--set", "host_ip=10.0.5.2", "--set", "lan_cidr=10.0.5.0/24", "--set",
               "lan_gateway=10.0.5.1", "--non-interactive"])
# covers: ask:cli.reinstall.confirm +
check("confirmed: a cold bundle, uninstall keeping the host's account, the bundle restored with the changes, setup",
      [c[0] for c in calls] == ["bundle", "uninstall", "restore", "setup"]
      and calls[0][1:] == ("reinstall", "cold", PASSPHRASE) and calls[1] == ("uninstall", False)
      and calls[2] == ("restore", BUNDLE, PASSPHRASE, {"host_ip": "10.0.5.2", "lan_cidr": "10.0.5.0/24",
                                                       "lan_gateway": "10.0.5.1"}), (rc, calls, out))
check("…setup gets its own options, not reinstall's", calls[-1][1] == ["setup", "--yes", "--non-interactive"], calls)
check("…and the changes are said before anything is done", "host_ip 10.0.0.5 -> 10.0.5.2" in out, out)

answer["v"] = "no"
rc, out = run(["--key-stdin"])
# covers: ask:cli.reinstall.confirm -
check("not confirmed: nothing stopped, nothing bundled", rc == 1 and calls == [] and "nothing changed" in out,
      (rc, calls))
answer["v"] = "yes"
rc, out = run(["--key-stdin", "--set", "hostname=fabric-2", "--yes"])
# covers: cli:reinstall -
check("negative: the host's name is not changed by a reinstall: refused before anything, pointing to 4.2.4.3",
      rc == 1 and calls == [] and "4.2.4.3" in out, (rc, calls, out))
rc, out = run(["--key-stdin", "--set", "host_ip=10.0.9.9", "--yes"])
check("negative: an address outside the subnet: refused before anything", rc == 1 and calls == []
      and "must both be in" in out, (rc, calls, out))
rc, out = run(["--key-stdin", "--yes"], stdin="short\n")
check("negative: a passphrase shorter than 12 characters: refused before anything", rc == 1 and calls == []
      and "shorter than 12" in out, (rc, calls, out))
rc, out = run(["--key-stdin", "--yes"], base=os.path.join(tmp, "nothing"))
check("negative: fabric not installed: refused", rc == 1 and calls == [] and "not installed" in out, (rc, out))
restore["fail"] = "age: no identity matched"
rc, out = run(["--key-stdin", "--yes"])
restore["fail"] = None
check("negative: the restore fails after the uninstall: the bundle is named with how to restore it, no setup",
      rc == 1 and calls[-1][0] == "restore" and BUNDLE in out and "fabricctl restore" in out, (rc, calls, out))

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
