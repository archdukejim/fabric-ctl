#!/usr/bin/env python3
"""A bundle made, checked and opened with the real age, zstd and tar (backup/make_bundle, check_bundle,
bundle_key_from, open_section; manual 1.3.7.2, decision 2.1.3.6). Root: owners and extended attributes are kept.

    sudo python3 tests/backup/bundle_test.py
"""
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.backup.bundle_key_from import bundle_key_from  # noqa: E402
from fabriclib.backup.check_bundle import check_bundle  # noqa: E402
from fabriclib.backup.make_bundle import make_bundle  # noqa: E402
from fabriclib.backup.open_section import open_section  # noqa: E402
from fabriclib.backup.section_paths import section_paths  # noqa: E402
from fabriclib.backup.sections import ORDER  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
PASSPHRASE = "test passphrase, not a real one"
META = {"fabric_version": "0.10.1", "commit": "test", "domain": "lab.test", "host_ip": "10.0.0.5",
        "lan_cidr": "10.0.0.0/24", "method": "cold"}


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


tmp = tempfile.mkdtemp()
base = os.path.join(tmp, "opt", "fabric")
folder = os.path.join(tmp, "backups")
zone = os.path.join(base, "bind9", "data", "db.lab.test")
os.makedirs(os.path.dirname(zone))
os.makedirs(os.path.join(base, "bind9", "ssl"))
with open(zone, "w") as f:
    f.write("$ORIGIN lab.test.\n@ 300 IN A 10.0.0.5\n")
os.chown(zone, 600, 600)
os.chmod(zone, 0o640)
with open(os.path.join(base, "bind9", "ssl", "bind9.key"), "w") as f:
    f.write("not a real key\n")
subprocess.run(["setfattr", "-n", "user.fabric", "-v", "kept", zone], check=False)
has_xattr = subprocess.run(["getfattr", "-n", "user.fabric", zone], capture_output=True).returncode == 0
plan = [(s, section_paths(s, base, {}), None) for s in ORDER]

path = make_bundle(plan, "fabric-test", META, "manual", passphrase=PASSPHRASE, folder=folder)
check("positive: the bundle is written 0600 in a 0700 folder",
      oct(os.stat(path).st_mode & 0o777) == "0o600" and oct(os.stat(folder).st_mode & 0o777) == "0o700")
check("positive: nothing else is left in the folder (no staging, no .part)",
      os.listdir(folder) == [os.path.basename(path)], os.listdir(folder))
with tarfile.open(path) as t:
    names = sorted(t.getnames())
    manifest = json.loads(t.extractfile("manifest.json").read())
    raw = b"".join(t.extractfile(n).read() for n in names if n.endswith(".age"))
check("positive: the bundle holds the manifest, README, key.age and the seven sections",
      names == sorted(["manifest.json", "README.txt", "key.age"] + [f"{s}.tar.zst.age" for s in ORDER]), names)
check("negative: no plain zone or key data anywhere in the bundle",
      b"lab.test." not in raw and b"not a real key" not in raw)
check("positive: the manifest names no passphrase and marks empty sections",
      PASSPHRASE not in json.dumps(manifest) and {e["name"]: e["empty"] for e in manifest["sections"]}["dhcp"]
      and not {e["name"]: e["empty"] for e in manifest["sections"]}["dns"])
check("positive: check_bundle passes a whole bundle", refused(lambda: check_bundle(path)) is None)

identity = bundle_key_from(path, passphrase=PASSPHRASE)
check("positive: the passphrase opens the bundle's key", identity.startswith("AGE-SECRET-KEY-1"))
check("negative: a wrong passphrase is refused", refused(lambda: bundle_key_from(path, passphrase="wrong")) is not None)
check("negative: neither a passphrase nor a key is refused", refused(lambda: bundle_key_from(path)) is not None)

out = os.path.join(tmp, "out")
os.makedirs(out)
open_section(path, "dns", identity, dest=out)
back = os.path.join(out, zone.lstrip("/"))
st = os.stat(back)
check("positive: the zone comes back with its content, owner and mode",
      open(back).read().startswith("$ORIGIN lab.test.") and (st.st_uid, st.st_gid) == (600, 600)
      and oct(st.st_mode & 0o777) == "0o640", (st.st_uid, st.st_gid, oct(st.st_mode)))
check("positive: its extended attribute too" if has_xattr else "positive: (no user xattrs on this file system)",
      not has_xattr or subprocess.run(["getfattr", "-n", "user.fabric", back], capture_output=True).returncode == 0)
check("negative: dns does not carry pki's bind9/ssl",
      not os.path.exists(os.path.join(out, base.lstrip("/"), "bind9", "ssl", "bind9.key")))
open_section(path, "pki", identity, dest=out)
check("positive: pki carries bind9/ssl",
      os.path.exists(os.path.join(out, base.lstrip("/"), "bind9", "ssl", "bind9.key")))
check("negative: a section opened with another bundle's key is refused",
      refused(lambda: open_section(path, "dns", "AGE-SECRET-KEY-1" + "Q" * 58, dest=out)) is not None)

keygen = subprocess.run(["age-keygen"], capture_output=True, text=True).stdout
private = next(line for line in keygen.splitlines() if line.startswith("AGE-SECRET-KEY-1"))
public = next(line.split(":", 1)[1].strip() for line in keygen.splitlines() if line.startswith("# public key:"))
sched = make_bundle(plan, "fabric-test", dict(META, method="online"), "scheduled", public_key=public, folder=folder)
check("positive: a scheduled bundle opens with the schedule's private key",
      bundle_key_from(sched, private_key=private).startswith("AGE-SECRET-KEY-1"))
check("negative: a scheduled bundle does not open with a passphrase",
      refused(lambda: bundle_key_from(sched, passphrase=PASSPHRASE)) is not None)
check("negative: a public key that is not age1… is refused, and nothing is written",
      refused(lambda: make_bundle(plan, "fabric-test", META, "manual", public_key="ssh-rsa AAAA", folder=folder))
      is not None and len(os.listdir(folder)) == 2, os.listdir(folder))
check("negative: both a passphrase and a public key are refused",
      refused(lambda: make_bundle(plan, "fabric-test", META, "manual", passphrase="x", public_key=public,
                                  folder=folder)) is not None)

bad = os.path.join(tmp, "tampered.fabric.tar")
shutil.copy(path, bad)
with tarfile.open(path) as t:
    member = t.getmember("dns.tar.zst.age")
with open(bad, "r+b") as f:                    # flip one byte inside dns's encrypted file
    f.seek(member.offset_data + member.size // 2)
    b = f.read(1)
    f.seek(-1, 1)
    f.write(bytes([b[0] ^ 1]))
check("negative: one changed byte in a section fails the check before any key is asked",
      "dns" in (refused(lambda: check_bundle(bad)) or ""))
with open(os.path.join(tmp, "plain.tar"), "wb") as f:
    f.write(b"not a tar")
check("negative: a file that is not a bundle is refused",
      refused(lambda: check_bundle(os.path.join(tmp, "plain.tar"))) is not None)
shutil.rmtree(tmp)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
