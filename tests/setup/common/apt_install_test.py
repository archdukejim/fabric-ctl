#!/usr/bin/env python3
"""Setup's apt installs (setup/common/apt_install): each apt waits for dpkg's lock (a fresh host's unattended-upgrades
holds it, the 0.10.0 rc's clean VM, 2.3.1.57); apt's failure is refused naming the packages and the hint. apt itself is
stood in for (pure logic: what is run, and what is said when it fails).

    python3 tests/setup/common/apt_install_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.setup.common.apt_install as m  # noqa: E402
from fabriclib.common.run import CommandError  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


RAN = []


def fake(cmd, env=None, timeout=600, **_):
    RAN.append((cmd, env, timeout))
    if FAIL_INSTALL and "install" in cmd:
        raise CommandError("E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1 (unattended-upgr)")


m.sh = fake
FAIL_INSTALL = False
m.apt_install(["sssd-ad", "krb5-user"], "check the sources")
update, install = RAN
check("positive: apt-get update waits for dpkg's lock", update[0][:3] == ["apt-get", "-o", "DPkg::Lock::Timeout=600"]
      and update[0][-1] == "update", update[0])
check("positive: the install waits for it too, then installs the packages without recommends",
      install[0] == ["apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "--no-install-recommends", "sssd-ad",
                     "krb5-user"], install[0])
check("positive: the wait fits inside each command's own time limit (600 s < 900 s, 1800 s)",
      update[2] == 900 and install[2] == 1800, (update[2], install[2]))
check("positive: apt runs without questions, needrestart automatic",
      install[1]["DEBIAN_FRONTEND"] == "noninteractive" and install[1]["NEEDRESTART_MODE"] == "a")

RAN.clear()
FAIL_INSTALL = True
try:
    m.apt_install(["sssd-ad"], "check the sources")
    said = "not refused"
except SetupError as e:
    said = str(e)
check("negative: the lock still held after the wait: refused, naming the packages, apt's error and the hint",
      "apt could not install sssd-ad" in said and "unattended-upgr" in said and said.endswith("check the sources"), said)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
