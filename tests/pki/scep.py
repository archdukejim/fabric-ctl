#!/usr/bin/env python3
"""Step-CA's SCEP provisioner as fabric configures it (manual 1.5.3.3), against the real Step-CA image: a CA made by
`step ca init`, the per-install RSA decrypter made by fabric's ensure_scep_ra (encrypted with its own password, made
once, kept while current), ca.json converged by init_pki._configure_ca_json (the provisioner `fabric-scep`, its two
webhooks on the console's name, no static challenge, the plain-HTTP listener; ca.json root-only), and Step-CA starting
with it and answering SCEP's GetCACaps and GetCACert with the decrypter's certificate. Without the web console the
provisioner and the plain-HTTP listener are taken out again.

A device's whole enrolment (a SCEP client sending a PKCSReq with the challenge) needs a device or a SCEP client in the
lab; it is not done here (notes 2.3.5.4).

    sudo python3 tests/pki/scep.py          (needs Docker, openssl, root)

Status: written for 0.9, not run yet (owner's direction of 2026-10-12; notes 2.3.5.4).
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

import jinja2

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.pki.scep.constants import PROVISIONER, RA_CERT, RA_KEY  # noqa: E402
from fabriclib.pki.scep.ensure_scep_ra import ensure_scep_ra  # noqa: E402
from fabriclib.setup.init_pki import _configure_ca_json  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki-scep"
IMAGE = os.environ.get("FABRIC_STEP_IMAGE") or subprocess.run(
    [sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
    capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
NAME, DOMAIN, PORT = "scep-ca", "lan.test", 19080          # GetCACaps from the host on 127.0.0.1:19080
RA_PASSWORD = "Ra-Test-" + os.urandom(8).hex()
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def cleanup():
    sh(["docker", "rm", "-f", NAME], ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
data = f"{W}/stepca/data"
os.makedirs(f"{data}/secrets")
os.makedirs(f"{data}/templates/certs")
os.makedirs(f"{data}/artifacts")
open(f"{data}/secrets/password", "w").write("Scep-Test-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/stepca"])
sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, "ca", "init", "--name=scep-test",
    f"--dns=ca.{DOMAIN},localhost", "--address=:9000", "--provisioner=admin",
    "--password-file=/home/step/secrets/password", "--provisioner-password-file=/home/step/secrets/password"])
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(REPO, "templates")))
for name in ("leaf", "acme"):                       # fabric's templates, rendered as setup renders them
    open(f"{data}/templates/certs/{name}.tpl", "w").write(env.get_template(f"stepca/{name}.tpl.j2").render(
        cert_country="US", cert_province="S", cert_city="C", cert_org="Test", cert_ou="IT",
        hostname_landing=f"info.{DOMAIN}", hostname_stepca=f"ca.{DOMAIN}", domain=DOMAIN))
v = {"deploy_base_dir": W, "hostname_stepca": f"ca.{DOMAIN}", "hostname_mgr": f"mgr.{DOMAIN}", "domain": DOMAIN,
     "install_webui": True, "scep_cert_days": 365, "cert_acme_lifetime_hours": "1128h",
     "stepca_cert_max_lifetime_hours": "1128h", "image_stepca": IMAGE,
     "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}}}
TMP = f"{W}/mint"
os.makedirs(TMP)


def mint(v_, cn, sans=(), days=365, kty="RSA", size=3072):
    """The RA's certificate from the intermediate, as mint_offline_cert issues it (openssl with the CA's password)."""
    key, csr, crt = f"{TMP}/{cn}.key", f"{TMP}/{cn}.csr", f"{TMP}/{cn}.crt"
    sh(["openssl", "genpkey", "-algorithm", kty, "-pkeyopt", f"rsa_keygen_bits:{size}", "-out", key])
    sh(["openssl", "req", "-new", "-key", key, "-subj", f"/CN={cn}", "-out", csr])
    open(f"{TMP}/ext", "w").write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n")
    sh(["openssl", "x509", "-req", "-in", csr, "-CA", f"{data}/certs/intermediate_ca.crt", "-CAkey",
        f"{data}/secrets/intermediate_ca_key", "-passin", f"file:{data}/secrets/password", "-CAcreateserial",
        "-days", str(days), "-out", crt, "-extfile", f"{TMP}/ext"])
    open(crt, "a").write(open(f"{data}/certs/intermediate_ca.crt").read())
    return crt, key


print("--- the decrypter (RA) key and certificate, per install")
made = ensure_scep_ra(v, RA_PASSWORD, STEP_UID, STEP_UID, mint=mint)
ra_crt, ra_key = f"{data}/certs/{RA_CERT}", f"{data}/secrets/{RA_KEY}"
text = sh(["openssl", "x509", "-in", ra_crt, "-noout", "-text"]).stdout
pw_file = f"{TMP}/pw"
open(pw_file, "w").write(RA_PASSWORD)
check("made: an RSA 3072 certificate from the intermediate, its key encrypted with scep_ra_password (0600)",
      made is True and "3072 bit" in text and sh(["openssl", "verify", "-partial_chain", "-CAfile",
                                                  f"{data}/certs/intermediate_ca.crt", ra_crt], ok=False).returncode == 0
      and "ENCRYPTED" in open(ra_key).read()
      and sh(["openssl", "pkey", "-in", ra_key, "-passin", f"file:{pw_file}", "-noout"], ok=False).returncode == 0
      and oct(os.stat(ra_key).st_mode & 0o777) == "0o600" and os.stat(ra_key).st_uid == STEP_UID, text[:300])
open(pw_file, "w").write("wrong")
check("negative: the key does not open with another password",
      sh(["openssl", "pkey", "-in", ra_key, "-passin", f"file:{pw_file}", "-noout"], ok=False).returncode != 0)
os.remove(pw_file)
check("kept while current: a second run makes nothing", ensure_scep_ra(v, RA_PASSWORD, STEP_UID, STEP_UID,
                                                                         mint=mint) is False)
check("no temporary key left behind", not any(n.endswith(".key") for n in os.listdir(TMP) if "scep-ra" in n),
      os.listdir(TMP))

print("--- ca.json converged with the SCEP provisioner")
CA_JSON = f"{data}/config/ca.json"
changed = _configure_ca_json(CA_JSON, v, RA_PASSWORD)
cfg = json.load(open(CA_JSON))
prov = next((p for p in cfg["authority"]["provisioners"] if p.get("name") == PROVISIONER), {})
hooks = {h["kind"]: h for h in prov.get("options", {}).get("webhooks", [])}
check("the provisioner: SCEP, our decrypter, no static challenge, forceCN, AES-256, scep_cert_days, fabric's leaf "
      "template; webhooks on the console's name; :9080; ca.json 0600",
      changed and prov.get("type") == "SCEP" and "challenge" not in prov and prov.get("forceCN") is True
      and prov.get("encryptionAlgorithmIdentifier") == 2 and prov.get("decrypterKeyPassword") == RA_PASSWORD
      and prov["claims"]["maxTLSCertDuration"] == "8760h"
      and prov["options"]["x509"]["templateFile"] == "/home/step/templates/certs/leaf.tpl"
      and hooks.get("SCEPCHALLENGE", {}).get("url") == f"https://mgr.{DOMAIN}/hooks/scep/challenge"
      and hooks.get("NOTIFYING", {}).get("url") == f"https://mgr.{DOMAIN}/hooks/scep/issued"
      and cfg.get("insecureAddress") == ":9080" and oct(os.stat(CA_JSON).st_mode & 0o777) == "0o600", prov)
check("converging again changes nothing", _configure_ca_json(CA_JSON, v, RA_PASSWORD) is False)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
sh(["docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{PORT}:9080", "-v", f"{data}:/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", IMAGE, "/usr/local/bin/step-ca", "/home/step/config/ca.json",
    "--password-file", "/home/step/secrets/password"])


def scep(operation):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/scep/{PROVISIONER}?operation={operation}",
                                timeout=10) as r:
        return r.status, r.headers.get("Content-Type", ""), r.read()


caps = None
for _ in range(30):
    time.sleep(1)
    try:
        caps = scep("GetCACaps")
        break
    except OSError:
        continue
logs = sh(["docker", "logs", NAME], ok=False)
check("Step-CA starts with it and answers GetCACaps over plain HTTP (POST, AES, SHA-256)",
      caps is not None and caps[0] == 200 and b"AES" in caps[2] and b"SHA-256" in caps[2] and b"POSTPKIOperation" in caps[2],
      (caps, (logs.stdout + logs.stderr)[-800:]))
st, ctype, body = scep("GetCACert") if caps else (0, "", b"")
open(f"{TMP}/cacert.der", "wb").write(body)
certs = sh(["openssl", "pkcs7", "-inform", "DER", "-in", f"{TMP}/cacert.der", "-print_certs"], ok=False).stdout
check("GetCACert: the decrypter's certificate (and the CA), for the device to encrypt its request to",
      st == 200 and "x-x509-ca-ra-cert" in ctype and f"scep-ra.{DOMAIN}" in certs, (st, ctype, certs[:300]))
sh(["docker", "rm", "-f", NAME], ok=False)

print("--- without the web console: no SCEP")
_configure_ca_json(CA_JSON, {**v, "install_webui": False}, None)
cfg = json.load(open(CA_JSON))
check("negative: the provisioner and the plain-HTTP listener are taken out",
      not any(p.get("name") == PROVISIONER for p in cfg["authority"]["provisioners"]) and "insecureAddress" not in cfg,
      cfg.get("insecureAddress"))
_configure_ca_json(CA_JSON, v, RA_PASSWORD)
_configure_ca_json(CA_JSON, v, None)
cfg = json.load(open(CA_JSON))
check("negative: without the decrypter's password (secrets not made yet) none either",
      not any(p.get("name") == PROVISIONER for p in cfg["authority"]["provisioners"]))

cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
