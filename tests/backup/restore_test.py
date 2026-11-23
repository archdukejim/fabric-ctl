#!/usr/bin/env python3
"""A whole restore from a bundle (backup/restore_bundle, run_restore_command's bundle form, the dump loaders; manual
1.3.7.6, 1.3.7.7): a real bundle of a temporary install, made and restored with the real age, zstd and tar; docker and
systemctl stood in for in the loaders. Root: owners are restored. The real services are the host suite's.

    sudo python3 tests/backup/restore_test.py
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.load_directory_dump as ldd  # noqa: E402
import fabriclib.backup.load_signin_dump as lsd  # noqa: E402
import fabriclib.backup.restore_bundle as rb  # noqa: E402
import fabriclib.setup.run_restore_command as rrc  # noqa: E402
from fabriclib.backup.make_bundle import make_bundle  # noqa: E402
from fabriclib.backup.restore_pending import read_restore_pending, write_restore_pending  # noqa: E402
from fabriclib.backup.section_paths import section_paths  # noqa: E402
from fabriclib.backup.sections import ORDER  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
PASS = "a passphrase for this test"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def refused(fn):
    try:
        fn()
    except ValidationError as exc:
        return str(exc)
    return None


audits = []
rb.write_audit = lambda *a, **k: audits.append(a)
here = {"problem": ""}                       # this test machine has none of the addresses: stood in for
rb.network_problem = lambda new: here["problem"]
tmp = tempfile.mkdtemp()
base = os.path.join(tmp, "opt", "fabric")
config = os.path.join(base, "fabric", "config")
os.makedirs(config)
os.makedirs(os.path.join(base, "bind9", "data"))
V = {"hostname": "fabric-1", "domain": "lab.test", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
     "lan_gateway": "10.0.0.1", "tsig_keys": [{"name": "npm"}], "dns_server": "10.0.0.1",
     "dns": {"lab.test": {"A": {"www": "10.0.0.5", "far": "192.0.2.7"}}},
     "dhcp": {"subnets": [{"subnet": "10.0.0.0/24", "routers": "10.0.0.1"}]}}
with open(os.path.join(config, "vars.yaml"), "w") as f:
    yaml.safe_dump(V, f)
with open(os.path.join(base, "bind9", "data", "db.lab.test"), "w") as f:
    f.write("@ IN A 10.0.0.5\n")
os.chown(os.path.join(base, "bind9", "data", "db.lab.test"), 600, 600)
folder = os.path.join(tmp, "backups")
META = {"fabric_version": "0.10.1", "commit": "t", "domain": "lab.test", "host_ip": "10.0.0.5",
        "lan_cidr": "10.0.0.0/24", "lan_gateway": "10.0.0.1", "base": base, "method": "cold"}
bundle = make_bundle([(s, section_paths(s, base, V), None, None) for s in ORDER], "fabric-1", META, "uninstall",
                     passphrase=PASS, folder=folder)
key = {"passphrase": PASS}
linked = make_bundle([(s, section_paths(s, base, V), None, None) for s in ORDER], "fabric-1", dict(META, linked=True),
                     "manual", passphrase=PASS, folder=folder)

check("negative: refused while fabric is installed, nothing touched",
      "fabric is installed here" in (refused(lambda: rb.restore_bundle(base, bundle, key)) or ""))
shutil.rmtree(base)
check("negative: a wrong passphrase: refused before anything is unpacked",
      refused(lambda: rb.restore_bundle(base, bundle, {"passphrase": "wrong one, long"})) is not None
      and not os.path.exists(base))
check("negative: a bundle from a newer fabric: refused, naming both versions",
      "newer than this package" in (refused(lambda: rb.restore_bundle(base, bundle, key, package_version="0.10.0"))
                                    or "") and not os.path.exists(base))
check("negative: another install root: refused",
      "not /srv/fabric" in (refused(lambda: rb.restore_bundle("/srv/fabric", bundle, key)) or ""))
check("negative: the host's name is not changed by a restore: refused before anything is unpacked (4.2.4.3)",
      "4.2.4.3" in (refused(lambda: rb.restore_bundle(base, bundle, key, {"hostname": "fabric-2"})) or "")
      and not os.path.exists(base))
here["problem"] = "10.0.5.2 is not an address of this machine (it has 10.0.0.5)"
check("negative: a new address this host does not have yet: refused before anything is unpacked, saying to "
      "re-address it first (4.2.4.8)",
      "4.2.4.8" in (refused(lambda: rb.restore_bundle(base, bundle, key, {"host_ip": "10.0.0.9"})) or "")
      and not os.path.exists(base))
here["problem"] = ""
partial = make_bundle([(s, section_paths(s, base, V) if s == "dns" else [], None, None) for s in ORDER], "fabric-1",
                      dict(META, only=["dns"]), "manual", passphrase=PASS, folder=folder)
check("negative: a section restore's safety bundle (dns only) restored whole: refused, naming --section, nothing unpacked",
      "holds only dns" in (refused(lambda: rb.restore_bundle(base, partial, key)) or "") and not os.path.exists(base))
os.remove(partial)
check("negative: a new address for an install with linked sites: refused (2.1.1.77)",
      "linked sites" in (refused(lambda: rb.restore_bundle(base, linked, key, {"host_ip": "10.0.0.9"})) or "")
      and not os.path.exists(base))
check("negative: an upstream DNS server that is not an address: refused",
      "not an address" in (refused(lambda: rb.restore_bundle(base, bundle, key, {"dns_server": "router"})) or ""))
check("negative: a gateway outside the new subnet: refused before anything is unpacked",
      "must both be in" in (refused(lambda: rb.restore_bundle(base, bundle, key, {"host_ip": "10.0.5.2",
                                                                            "lan_cidr": "10.0.5.0/24"})) or "")
      and not os.path.exists(base))
out = rb.restore_bundle(base, bundle, key, {"host_ip": "10.0.5.2", "lan_cidr": "10.0.5.0/24",
                                           "lan_gateway": "10.0.5.1", "dns_server": "10.0.5.1"},
                       package_version="0.10.1")
with open(os.path.join(config, "vars.yaml")) as f:
    back = yaml.safe_load(f)
st = os.stat(os.path.join(base, "bind9", "data", "db.lab.test"))
check("positive: every section back in place, owners kept", (st.st_uid, st.st_gid) == (600, 600))
check("positive: the new address, subnet and gateway written; the rest as it was",
      back["host_ip"] == "10.0.5.2" and back["lan_cidr"] == "10.0.5.0/24" and back["lan_gateway"] == "10.0.5.1"
      and back["tsig_keys"] == [{"name": "npm"}] and back["domain"] == "lab.test", back)
check("positive: the changes reported old to new", out["changed"]["host_ip"] == ("10.0.0.5", "10.0.5.2")
      and back["dns_server"] == "10.0.5.1", out["changed"])
check("positive: what still names the old address or subnet is listed: the admin's record, DHCP's old subnet and "
      "router; not a record elsewhere, not the changed settings",
      dict(out["leftover"]) == {"dns.lab.test.A.www": "10.0.0.5", "dhcp.subnets.0.subnet": "10.0.0.0/24",
                                "dhcp.subnets.0.routers": "10.0.0.1"}, out["leftover"])
check("positive: a cold bundle leaves no dump pending for setup; the plan's LAN subnet is to move with the subnet",
      read_restore_pending(config) == {"plan_move": {"from": "10.0.0.0/24", "to": "10.0.5.0/24"}},
      read_restore_pending(config))
check("positive: audited as RESTORE", audits and audits[-1][1] == "RESTORE", audits)

# run_restore_command's bundle form, setup's exec stood in for
shutil.rmtree(base)
execs = []


class _OS:
    """os for run_restore_command alone, with setup's exec stood in for (os.execv itself stays: age's pty child
    needs it)."""
    execv = staticmethod(lambda exe, argv: execs.append(argv))

    def __getattr__(self, name):
        return getattr(os, name)


rrc.os = _OS()
rrc.ask = lambda qid, prompt, default=None: "no"
real_stdin = sys.stdin
sys.stdin = io.StringIO(PASS + "\n")
code = rrc.run_restore_command([bundle, "--key-stdin"], base, "/usr/lib/fabricctl/fabric/lib/fabriclib/cli.py")
# covers: ask:restore.confirm_bundle -
check("negative: not confirmed: nothing restored", code == 1 and not os.path.exists(base) and not execs, code)
rrc.ask = lambda qid, prompt, default=None: "yes"
sys.stdin = io.StringIO(PASS + "\n")
code = rrc.run_restore_command([bundle, "--key-stdin", "--set", "lan_gateway=10.0.0.254"], base,
                               "/usr/lib/fabricctl/fabric/lib/fabriclib/cli.py")
sys.stdin = real_stdin
# covers: ask:restore.confirm_bundle +
check("positive: confirmed: restored with the change, then setup runs unattended",
      execs and execs[-1][2:5] == ["setup", "--yes", "--non-interactive"]
      and yaml.safe_load(open(os.path.join(config, "vars.yaml")))["lan_gateway"] == "10.0.0.254", (code, execs))
shutil.rmtree(base)
asked = []
rrc.ask = lambda qid, prompt, default=None: asked.append(qid) or ("" if qid == "restore.approve_move" else "yes")
rrc.load_consent = lambda d: {"firewall": {"answer": "yes"}, "ports": {"answer": "yes"}, "time": {"answer": "no"}}
sys.stdin = io.StringIO(PASS + "\n")
code = rrc.run_restore_command([bundle, "--key-stdin", "--set", "host_ip=10.0.0.9"], base, "cli.py")
sys.stdin = real_stdin
# covers: ask:restore.approve_move +
check("positive: a new address: asked first whether host changes allowed before are allowed again; yes approves "
      "only those (a declined one stays declined)",
      asked[:2] == ["restore.approve_move", "restore.confirm_bundle"] and execs
      and execs[-1][execs[-1].index("--approve") + 1] == "firewall,ports", (asked, execs))
shutil.rmtree(base)
rrc.ask = lambda qid, prompt, default=None: "n" if qid == "restore.approve_move" else "yes"
sys.stdin = io.StringIO(PASS + "\n")
code = rrc.run_restore_command([bundle, "--key-stdin", "--set", "host_ip=10.0.0.9"], base, "cli.py")
sys.stdin = real_stdin
# covers: ask:restore.approve_move -
check("negative: not allowed again: setup gets no approval (it stops and asks, global Rule 12)",
      execs and "--approve" not in execs[-1], execs)
code = rrc.run_restore_command([bundle, "--set", "host_ip"], base, "cli.py")
check("negative: --set without key=value is refused", code == 1, code)

# the dump loaders: what setup does with an online bundle's dumps
pend = os.path.join(tmp, "config")
os.makedirs(pend)
check("positive: nothing pending: no file", read_restore_pending(pend) == {})
calls = []


def fake_run(cmd, **kw):
    calls.append(cmd)
    if "pg_restore" in cmd:
        return subprocess.CompletedProcess(cmd, 1 if "fail" in calls[0] else 0, b"", b"pg_restore: error: bad")
    return subprocess.CompletedProcess(cmd, 0, "backup marks removed: backupDate", "")


lsd.subprocess = ldd.subprocess = type("S", (), {"run": staticmethod(fake_run), "CompletedProcess":
                                                 subprocess.CompletedProcess})
dump = os.path.join(tmp, "keycloak.pgdump")
open(dump, "wb").write(b"PGDMP")
write_restore_pending(pend, {"signin": dump})
check("positive: Keycloak's dump loaded with pg_restore, crossed off, removed",
      lsd.load_signin_dump(pend) and any("pg_restore" in c for c in calls) and read_restore_pending(pend) == {}
      and not os.path.exists(dump), calls)
check("positive: nothing pending: no restore runs", lsd.load_signin_dump(pend) is False)

samba = os.path.join(base, "samba", "data", "private")
os.makedirs(samba, exist_ok=True)
copy = os.path.join(tmp, "samba-backup-x.tar.bz2")
with tarfile.open(copy, "w:bz2") as t:
    for name, data in (("private/sam.ldb", b"restored sam"), ("state/registry.tdb", b"reg"), ("SHA256SUM", b"x")):
        info = tarfile.TarInfo(name)
        info.size, info.mode = len(data), 0o600
        t.addfile(info, io.BytesIO(data))
write_restore_pending(pend, {"directory": copy})
calls.clear()
check("positive: the domain's copy put in place before the DC starts, its marks removed in the DC's image",
      ldd.load_directory_dump(base, pend) and open(os.path.join(samba, "sam.ldb"), "rb").read() == b"restored sam"
      and any(c[:2] == ["docker", "compose"] and "/fabric/finish_restore.py" in c for c in calls)
      and read_restore_pending(pend) == {}, calls)
check("positive: BIND's copy of the DNS partitions, which the copy does not bring, made again in the DC's image",
      any("/fabric/make_bind_dns.py" in c for c in calls), calls)
os.makedirs(os.path.join(base, "samba", "data", "bind-dns", "dns"), exist_ok=True)
open(os.path.join(base, "samba", "data", "bind-dns", "dns", "sam.ldb"), "w").close()
with tarfile.open(copy, "w:bz2") as t:
    info = tarfile.TarInfo("private/sam.ldb")
    info.size, info.mode = 3, 0o600
    t.addfile(info, io.BytesIO(b"sam"))
write_restore_pending(pend, {"directory": copy})
calls.clear()
check("negative: BIND's copy already there (a cold bundle's): left as it is",
      ldd.load_directory_dump(base, pend) and not any("/fabric/make_bind_dns.py" in c for c in calls), calls)
check("negative: files outside private/, state/ and etc/ are not taken",
      not os.path.exists(os.path.join(base, "samba", "data", "SHA256SUM")))
evil = os.path.join(tmp, "samba-backup-evil.tar.bz2")
with tarfile.open(evil, "w:bz2") as t:
    info = tarfile.TarInfo("private/../../../../etc/passwd-x")
    info.size = 1
    t.addfile(info, io.BytesIO(b"x"))
write_restore_pending(pend, {"directory": evil})
check("negative: a copy naming a path outside the DC's data is refused, and stays pending",
      "outside the DC's data" in (refused(lambda: ldd.load_directory_dump(base, pend)) or "")
      and json.load(open(os.path.join(pend, "restore-pending.json"))) == {"directory": evil})
shutil.rmtree(tmp)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
