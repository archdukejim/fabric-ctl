"""The federation endpoint's unit installed when it changed (`federation/deploy_federation_endpoint`, manual 1.9.4.2):
a new unit installed and reported, an unchanged one not, a same-size change within one mtime tick installed
(2.3.1.29: `filecmp.cmp`'s cache missed it). The unit's path and the install root are a temporary folder; nothing of
systemd's is touched (the endpoint is on, so the code never calls systemctl). Runs as root (it chowns to root).
    sudo python3 tests/federation/deploy_federation_endpoint_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.federation.deploy_federation_endpoint as dfe  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


if os.geteuid() != 0:
    print("FAIL needs root: it chowns the unit and the socket folder to root")
    sys.exit(1)
with tempfile.TemporaryDirectory() as t:
    dfe.UNIT_PATH = os.path.join(t, "etc", "fabric-federation.service")
    os.makedirs(os.path.dirname(dfe.UNIT_PATH))
    render, base = os.path.join(t, "render"), os.path.join(t, "opt")
    unit = os.path.join(render, "systemd", "fabric-federation.service")
    v = {"federation_endpoint": True, "service_users": {"nginx": {"gid": os.getgid()}}}
    write(unit, "ExecStart=a\n")
    res = dfe.deploy_federation_endpoint(v, render, base)
    check("positive: a new unit is installed and reported", res == {"unit_changed": True, "removed": False}
          and open(dfe.UNIT_PATH).read() == "ExecStart=a\n", res)
    res = dfe.deploy_federation_endpoint(v, render, base)
    check("negative: the same unit again: not reported", res == {"unit_changed": False, "removed": False}, res)
    before = os.stat(unit)
    write(unit, "ExecStart=b\n")
    os.utime(unit, ns=(before.st_atime_ns, before.st_mtime_ns))
    res = dfe.deploy_federation_endpoint(v, render, base)
    check("positive: a same-size change in the same mtime tick is installed and reported",
          res["unit_changed"] and open(dfe.UNIT_PATH).read() == "ExecStart=b\n", res)
    os.utime(unit, ns=(before.st_atime_ns + 5 * 10**9, before.st_mtime_ns + 5 * 10**9))
    res = dfe.deploy_federation_endpoint(v, render, base)
    check("negative: only the mtime moved: not reported", res["unit_changed"] is False, res)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
