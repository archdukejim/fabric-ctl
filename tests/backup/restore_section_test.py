#!/usr/bin/env python3
"""One section restored on a running install (backup/restore_section, run_restore_command's --section; manual
1.3.7.8): real bundles of a temporary install, made and opened with the real age, zstd and tar; the safety bundle,
systemctl, the apply and the dump loaders stood in for. Root: owners are restored, the lock and dumps live in /run.
The real services are the host suite's.

    sudo python3 tests/backup/restore_section_test.py
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fabriclib.backup.restore_section as rs  # noqa: E402
import fabriclib.setup.run_restore_command as rrc  # noqa: E402
from fabriclib.backup.backup_plan import DUMPS  # noqa: E402
from fabriclib.backup.make_bundle import make_bundle  # noqa: E402
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


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def read(path):
    with open(path) as f:
        return f.read()


safeties, audits, applies, calls, loaded = [], [], [], [], []


def fake_make_backup(base, v, secrets_file, kind, method, **kw):
    safeties.append((kind, method, kw))
    return "/var/backups/fabric/fabric-1-safety.fabric.tar"


def fake_run(cmd, **kw):
    calls.append(cmd)
    return subprocess.CompletedProcess(cmd, 0, b"", b"")


rs.make_backup = fake_make_backup
rs.write_audit = lambda *a, **k: audits.append(a)
rs.subprocess = type("S", (), {"run": staticmethod(fake_run), "CompletedProcess": subprocess.CompletedProcess})
rs.systemctl_up = lambda units, **k: calls.append(["up", *units])
rs.load_signin_dump = lambda config_dir: loaded.append("signin")
rs.load_directory_dump = lambda base, config_dir: loaded.append("directory")

tmp = tempfile.mkdtemp()
base = os.path.join(tmp, "opt", "fabric")
config = os.path.join(base, "fabric", "config")
V = {"hostname": "fabric-1", "site_name": "lab", "domain": "lab.test", "host_ip": "10.0.0.5",
     "lan_cidr": "10.0.0.0/24", "lan_gateway": "10.0.0.1", "tsig_keys": [{"name": "npm"}], "ntp_servers": ["a"],
     "postgres_data_dir": os.path.join(base, "postgres", "data")}
os.makedirs(config)
with open(os.path.join(config, "vars.yaml"), "w") as f:
    yaml.safe_dump(V, f)
zone = os.path.join(base, "bind9", "data", "db.lab.test")
cert = os.path.join(base, "bind9", "ssl", "bind.crt")
pg = os.path.join(base, "postgres", "data", "PG_VERSION")
kc = os.path.join(base, "keycloak", "conf", "keycloak.conf")
write(zone, "@ IN A 10.0.0.5\n")
write(cert, "the bundle's cert\n")
write(pg, "17\n")
write(kc, "the bundle's keycloak\n")
os.chown(zone, 600, 600)
META = {"fabric_version": "0.10.1", "domain": "lab.test", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
        "lan_gateway": "10.0.0.1", "base": base, "method": "cold"}
folder = os.path.join(tmp, "backups")
bundle = make_bundle([(s, section_paths(s, base, V), None, None) for s in ORDER], "fabric-1", META, "manual",
                     passphrase=PASS, folder=folder)
# an online bundle: Postgres's live folder left out, Keycloak's dump beside the section
shutil.rmtree(DUMPS, ignore_errors=True)
write(os.path.join(DUMPS, "signin", "keycloak.pgdump"), "PGDMP")
online = make_bundle([(s, [(p, k + ([os.path.dirname(pg)] if s == "signin" else []))
                           for p, k in section_paths(s, base, V)], os.path.join(DUMPS, s) if s == "signin" else None,
                       None) for s in ORDER], "fabric-1", dict(META, method="online"), "manual", passphrase=PASS,
                     folder=folder + "-online")
shutil.rmtree(DUMPS, ignore_errors=True)
key = {"passphrase": PASS}


def go(section, path=bundle, version="0.10.1", k=None, b=base):
    return rs.restore_section(b, config, path, section, k or key, version, apply=lambda: applies.append(section))


# after the bundle: the zone and the TSIG keys changed, a stray file added, pki's cert and a settings key changed
write(zone, "@ IN A 10.9.9.9\n")
write(os.path.join(base, "bind9", "data", "db.made-after"), "x\n")
write(cert, "a newer cert\n")
with open(os.path.join(config, "vars.yaml"), "w") as f:
    yaml.safe_dump(dict(V, tsig_keys=[{"name": "npm"}, {"name": "later"}], ntp_servers=["b"]), f)

check("negative: secrets alone is refused (2.1.1.106 point 2), no safety bundle made",
      "whole bundle" in (refused(lambda: go("secrets")) or "") and not safeties)
check("negative: an unknown section is refused, naming the seven",
      "one of settings" in (refused(lambda: go("mail")) or "") and not safeties)
check("negative: a bundle of another fabric version is refused, naming both",
      "0.10.2" in (refused(lambda: go("dns", version="0.10.2")) or "") and not safeties)
check("negative: a bundle of another install root is refused",
      "not /srv/fabric" in (refused(lambda: go("dns", b="/srv/fabric")) or "") and not safeties)
check("negative: a wrong passphrase is refused before the safety bundle or anything else",
      refused(lambda: go("dns", k={"passphrase": "wrong one, long"})) is not None and not safeties
      and read(zone) == "@ IN A 10.9.9.9\n")

out = go("dns")
back = yaml.safe_load(open(os.path.join(config, "vars.yaml")))
check("positive: a safety bundle of the section and settings first, sealed with the same passphrase",
      safeties and safeties[0][2].get("passphrase") == PASS and safeties[0][2].get("only") == {"dns", "settings"},
      safeties)
check("positive: the zone back as it was, owner kept", read(zone) == "@ IN A 10.0.0.5\n"
      and (os.stat(zone).st_uid, os.stat(zone).st_gid) == (600, 600))
check("positive: what was made after the bundle is gone",
      not os.path.exists(os.path.join(base, "bind9", "data", "db.made-after")))
check("positive: pki's folder inside bind9 is left as it is", read(cert) == "a newer cert\n")
check("positive: dns's keys replaced, other sections' keys kept",
      back["tsig_keys"] == [{"name": "npm"}] and back["ntp_servers"] == ["b"] and "tsig_keys" in out["keys"], back)
check("positive: the DNS units that were running stopped, then started again",
      ["systemctl", "stop", "bind9", "bind9-resolver", "adguard-filter"] in calls
      and ["up", "bind9", "bind9-resolver", "adguard-filter"] in calls, calls)
check("positive: an apply runs, and it is audited as RESTORE_SECTION",
      applies == ["dns"] and audits and audits[-1][1] == "RESTORE_SECTION" and "section=dns" in audits[-1][2],
      (applies, audits))

write(pg, "17 and newer rows\n")
write(kc, "a newer keycloak\n")
loaded.clear()
go("signin", path=online)
check("positive: an online sign-in section: Keycloak's files back, Postgres's live folder left in place",
      read(kc) == "the bundle's keycloak\n" and read(pg) == "17 and newer rows\n")
check("positive: its dump loaded into the running database, and the dumps cleared from RAM",
      loaded == ["signin"] and not os.path.exists(DUMPS), loaded)

# run_restore_command's --section form
rrc.restore_section = lambda *a, **k: (calls.append(["restore", a[3]]), {"safety": "/s.fabric.tar"})[1]
rrc.ask = lambda qid, prompt, default=None: "not the name"
real_stdin = sys.stdin
sys.stdin = io.StringIO(PASS + "\n")
calls.clear()
code = rrc.run_restore_command([bundle, "--section", "dns", "--key-stdin"], base, "cli.py")
# covers: ask:restore.confirm_section -
check("negative: the site's name not typed: nothing restored", code == 1 and not calls, (code, calls))
rrc.ask = lambda qid, prompt, default=None: "lab"
sys.stdin = io.StringIO(PASS + "\n")
code = rrc.run_restore_command([bundle, "--section", "dns", "--key-stdin"], base, "cli.py")
sys.stdin = real_stdin
# covers: ask:restore.confirm_section +
check("positive: the site's name typed: that section restored", code == 0 and ["restore", "dns"] in calls,
      (code, calls))
shutil.rmtree(base)
calls.clear()
code = rrc.run_restore_command([bundle, "--section", "dns", "--yes"], base, "cli.py")
check("negative: --section where fabric is not installed is refused", code == 1 and not calls, code)
shutil.rmtree(tmp)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
