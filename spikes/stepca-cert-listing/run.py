#!/usr/bin/env python3
"""Prototype for 2.1.5.13 (manual 2.3.5.5): can fabric list the certificates Step-CA issues over ACME?

Throwaway (global Rule 4): never merged into src/. It makes a CA as tests/pki/acme.py does (the real Step-CA image,
fabric's own ca.json converge and templates), has a LAN machine get one certificate over ACME, and one over the JWK
provisioner as setup does, then tries:

  A. Step-CA's own database: read with smallstep/nosql (the library Step-CA itself uses), live and from a copy,
     before and after a restart.
  B. Step-CA's log: whether each issuance is logged with its serial and provisioner.

    sudo python3 spikes/stepca-cert-listing/run.py     (needs Docker, root, network for the Go module)
"""
import json
import os
import shutil
import subprocess
import sys
import time

import jinja2

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.setup.init_pki import _configure_ca_json  # noqa: E402

W = "/tmp/fabric-spike-certlist"
IMAGE = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
                       capture_output=True, text=True, check=True).stdout.strip()
GO_IMAGE = "golang:1.23.4"
STEP_UID, DOMAIN = 1912, "lan.test"
NET, CA, MACHINE = "spike-certlist", "spike-certlist-ca", "spike-certlist-machine"
FOUND = []


def note(name, ok, detail=""):
    FOUND.append((name, ok))
    print(("YES  " if ok else "NO   ") + name + (f"\n     {str(detail)[:900]}" if detail else ""))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stdout[-800:]}\n{res.stderr[-800:]}")
    return res


def cleanup():
    for c in (CA, MACHINE):
        sh(["docker", "rm", "-f", c], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


def serial_of(pem):
    out = sh(["openssl", "x509", "-noout", "-serial"], input=pem).stdout.strip()
    return out.split("=", 1)[1].lower().lstrip("0")


def read_db(path, label):
    """Run the Go reader against a database directory; returns (ok, rows or error text)."""
    res = sh(["docker", "run", "--rm", "--network", "bridge", "-v", f"{HERE}/reader:/src:ro", "-v", f"{path}:/db",
              "-v", f"{W}/gocache:/root/go", "-w", "/work", GO_IMAGE, "sh", "-c",
              "cp /src/* /work/ && go mod tidy >/dev/null 2>&1 && go run . /db"], ok=False)
    if res.returncode != 0:
        return False, (res.stderr or res.stdout)[-900:]
    rows = [json.loads(line) for line in res.stdout.splitlines() if line.startswith("{")]
    print(f"     {label}: {len(rows)} certificate(s) in x509_certs")
    return True, rows


def health():
    for _ in range(30):
        time.sleep(1)
        if sh(["docker", "exec", CA, "step", "ca", "health", "--ca-url", "https://localhost:9000", "--root",
               "/home/step/certs/root_ca.crt"], ok=False).stdout.strip() == "ok":
            return True
    return False


cleanup()
shutil.rmtree(W, ignore_errors=True)
data = f"{W}/stepca/data"
os.makedirs(f"{data}/secrets")
os.makedirs(f"{data}/templates/certs")
os.makedirs(f"{W}/gocache")
open(f"{data}/secrets/password", "w").write("Spike-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/stepca"])
sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, "ca", "init", "--name=spike",
    f"--dns=ca.{DOMAIN},localhost", "--address=:9000", "--provisioner=admin",
    "--password-file=/home/step/secrets/password", "--provisioner-password-file=/home/step/secrets/password"])
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(REPO, "templates")))
for name in ("leaf", "acme"):
    open(f"{data}/templates/certs/{name}.tpl", "w").write(env.get_template(f"stepca/{name}.tpl.j2").render(
        cert_country="US", cert_province="S", cert_city="C", cert_org="Test", cert_ou="IT",
        hostname_landing=f"info.{DOMAIN}", hostname_stepca=f"ca.{DOMAIN}", domain=DOMAIN))
_configure_ca_json(f"{data}/config/ca.json", {"hostname_stepca": f"ca.{DOMAIN}", "domain": DOMAIN,
                                              "cert_acme_lifetime_hours": "1128h",
                                              "stepca_cert_max_lifetime_hours": "1128h"})
print("ca.json db:", json.load(open(f"{data}/config/ca.json")).get("db"))
print("image:", IMAGE)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
sh(["docker", "network", "create", NET])
sh(["docker", "run", "-d", "--name", CA, "--network", NET, "--network-alias", f"ca.{DOMAIN}", "-v",
    f"{data}:/home/step", "--user", f"{STEP_UID}:{STEP_UID}", IMAGE, "/usr/local/bin/step-ca",
    "/home/step/config/ca.json", "--password-file", "/home/step/secrets/password"])
assert health(), "Step-CA did not start"
print("step-ca version:", sh(["docker", "exec", CA, "step-ca", "version"], ok=False).stdout.strip().replace("\n", " "))
sh(["docker", "run", "-d", "--name", MACHINE, "--network", NET, "--network-alias", f"nas.{DOMAIN}", "--user", "0:0",
    "-v", f"{data}/certs/root_ca.crt:/root_ca.crt:ro", "--entrypoint", "sleep", IMAGE, "600"])

# one certificate over ACME (http-01), one over JWK as setup mints a service certificate
sh(["docker", "exec", MACHINE, "step", "ca", "certificate", f"nas.{DOMAIN}", "/tmp/nas.crt", "/tmp/nas.key",
    "--provisioner", "acme", "--ca-url", f"https://ca.{DOMAIN}:9000", "--root", "/root_ca.crt", "--standalone",
    "--http-listen", ":80", "--force"])
acme_serial = serial_of(sh(["docker", "exec", MACHINE, "cat", "/tmp/nas.crt"]).stdout)
sh(["docker", "exec", CA, "step", "ca", "certificate", f"svc.{DOMAIN}", "/tmp/svc.crt", "/tmp/svc.key",
    "--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt", "--provisioner", "admin",
    "--provisioner-password-file", "/home/step/secrets/password", "--force", "--not-after", "24h"])
jwk_serial = serial_of(sh(["docker", "exec", CA, "cat", "/tmp/svc.crt"]).stdout)
print(f"issued: acme {acme_serial}, jwk {jwk_serial}")


def judge(label, ok, rows):
    if not ok:
        note(f"A ({label}): the database can be read", False, rows)
        return
    by = {r["serial"].lower().lstrip("0"): r for r in rows}
    note(f"A ({label}): the ACME certificate is listed, with its provisioner",
         acme_serial in by and bool(by[acme_serial].get("provisioner")), by.get(acme_serial) or sorted(by)[:5])
    note(f"A ({label}): the JWK certificate is listed, with its provisioner",
         jwk_serial in by and bool(by[jwk_serial].get("provisioner")), by.get(jwk_serial))


# A, live: Step-CA holds the database open
ok, rows = read_db(f"{data}/db", "live")
note("A (live, Step-CA running): the database opens beside Step-CA", ok, "" if ok else rows)
# A, a copy taken while Step-CA runs
shutil.copytree(f"{data}/db", f"{W}/db-copy")
ok, rows = read_db(f"{W}/db-copy", "copy while running")
judge("copy while running", ok, rows)
# B, the log
log = sh(["docker", "logs", CA], ok=False)
text = log.stdout + log.stderr
lines = [line for line in text.splitlines() if acme_serial in line.lower().replace(":", "") or
         str(int(acme_serial, 16)) in line]
note("B: the ACME issuance is in Step-CA's log with its serial", bool(lines), (lines[:2] or text[-900:]))
note("B: …and names the provisioner", any("acme" in line for line in lines), lines[:1])
# A, after a restart, stopped and then running again
sh(["docker", "stop", CA])
ok, rows = read_db(f"{data}/db", "Step-CA stopped")
judge("Step-CA stopped", ok, rows)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
sh(["docker", "start", CA])
assert health(), "Step-CA did not come back"
shutil.rmtree(f"{W}/db-copy2", ignore_errors=True)
shutil.copytree(f"{data}/db", f"{W}/db-copy2")
ok, rows = read_db(f"{W}/db-copy2", "copy after restart")
judge("copy after restart", ok, rows)
cleanup()
print("\nSUMMARY")
for name, ok in FOUND:
    print(("YES  " if ok else "NO   ") + name)
