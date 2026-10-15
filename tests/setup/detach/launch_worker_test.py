"""launch_worker (decision 2.1.2.26, manual 1.3.2.3.4): systemd-run starts fabric-setup.service with --collect and
the run's log, and its command line and environment carry no secret (systemctl show prints both to any user).
systemd-run is stubbed.
    python3 tests/setup/detach/launch_worker_test.py"""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
from fabriclib.setup.detach.launch_worker import CLI, launch_worker  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


calls = []


def ok_run(cmd, **kw):
    calls.append(cmd)
    return SimpleNamespace(returncode=0, stdout="", stderr="")


env = {"SUDO_USER": "alice", "SSH_CONNECTION": "192.0.2.9 50000 192.0.2.5 22", "ADMIN_PASSWORD": "Good-Pass-1234",
       "FABRIC_SECRET": "s3cret", "PATH": "/usr/bin"}
launch_worker("20261015-120000-abc123", "/opt", "/opt/fabric/config/setup-run.log", env=env, run=ok_run)
cmd = calls[-1]
check("systemd-run starts fabric-setup.service, collected when it ends (nothing left behind, Rule 12)",
      cmd[0] == "systemd-run" and "--unit=fabric-setup.service" in cmd and "--collect" in cmd, cmd)
check("its output and errors are appended to the run's log",
      "StandardOutput=append:/opt/fabric/config/setup-run.log" in cmd
      and "StandardError=append:/opt/fabric/config/setup-run.log" in cmd, cmd)
tail = cmd[cmd.index("--") + 1:]
check("it runs this code's cli.py: setup --worker <run> --deploy-base <base>",
      tail[1:] == [CLI, "setup", "--worker", "20261015-120000-abc123", "--deploy-base", "/opt"]
      and CLI.endswith(os.path.join("fabriclib", "cli.py")), tail)
check("only SUDO_USER and SSH_CONNECTION are passed from the console's environment (names, never secrets)",
      "--setenv=SUDO_USER=alice" in cmd and "--setenv=SSH_CONNECTION=192.0.2.9 50000 192.0.2.5 22" in cmd
      and not any("PATH=/usr/bin" in a for a in cmd), cmd)
check("negative: no secret from the environment reaches the unit's command line or environment",
      not any("Good-Pass-1234" in a or "s3cret" in a or "PASSWORD" in a for a in cmd), cmd)
launch_worker("r2", "/opt", "/x.log", env={}, run=ok_run)
check("without SUDO_USER or SSH_CONNECTION nothing empty is passed",
      not any(a.startswith("--setenv=SUDO_USER") or a.startswith("--setenv=SSH_CONNECTION") for a in calls[-1]))


def refused(cmd, **kw):
    return SimpleNamespace(returncode=1, stdout="", stderr="Failed to start transient service unit: Unit "
                           "fabric-setup.service was already loaded or has a fragment file.")


try:
    launch_worker("r3", "/opt", "/x.log", env={}, run=refused)
    check("negative: systemd refusing the unit is a SetupError naming its message", False)
except SetupError as e:
    check("negative: systemd refusing the unit is a SetupError naming its message",
          "could not start fabric-setup.service" in str(e) and "already loaded" in str(e), e)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
