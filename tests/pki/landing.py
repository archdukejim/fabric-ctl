#!/usr/bin/env python3
"""The landing page's certificate follows the zone (decision 2.1.4.8, manual 1.4.2.6), against the real Step-CA image
running as setup runs it (a container named step-ca, the JWK provisioner `admin`): setup's `certs` step issues it for
the host's own name, <domain> and the admin's aliases of the host; an apply that finds its names changed (the info
alias renamed) issues it again at once, without the old name, and does not revoke the one it replaced (2.1.4.8,
revised 2026-10-12: it expires; the CRL does not list it); and the refusals: nothing issued while the names are
current or before the first certificate exists, a record pointing at another machine or one of fabric's own names
never on it, an apply whose certificate cannot be issued failing loudly with the certificate unchanged.

    sudo python3 tests/pki/landing.py          (needs Docker, openssl, root; uses the container name step-ca)
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import time

import jinja2
import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki-landing"
IMAGE = os.environ.get("FABRIC_STEP_IMAGE") or subprocess.run(
    [sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
    capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
LABEL = "fabric-test=pki-landing"
DOMAIN, IP = "lan.test", "192.168.7.53"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:500]}"))


def sh(cmd, ok=True):
    res = subprocess.run(cmd, capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def cleanup():
    """Remove this test's step-ca only (labelled): never a step-ca container it did not start."""
    ours = sh(["docker", "ps", "-aq", "--filter", "name=^step-ca$", "--filter", f"label={LABEL}"], ok=False).stdout
    if ours.strip():
        sh(["docker", "rm", "-f", "step-ca"], ok=False)


cleanup()
if sh(["docker", "ps", "-aq", "--filter", "name=^step-ca$"], ok=False).stdout.strip():
    print("FAIL a container named step-ca that this test did not start exists: the test needs the name (mint_cert)")
    sys.exit(1)

# ---------------------------------------------------------------- an install's layout, a CA made by step ca init
shutil.rmtree(W, ignore_errors=True)
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)   # the installed tree: INSTALL_DIR
data = f"{W}/stepca/data"
os.makedirs(f"{data}/secrets")
os.makedirs(f"{data}/templates/certs")
os.makedirs(f"{W}/fabric/config", exist_ok=True)
open(f"{data}/secrets/password", "w").write("Landing-Test-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/stepca"])
sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, "ca", "init", "--name=landing-test",
    f"--dns=ca.{DOMAIN},localhost,127.0.0.1", "--address=:9000", "--provisioner=admin",
    "--password-file=/home/step/secrets/password", "--provisioner-password-file=/home/step/secrets/password"])
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(REPO, "templates")))
for name in ("leaf", "acme"):                       # fabric's templates, rendered as setup renders them
    open(f"{data}/templates/certs/{name}.tpl", "w").write(env.get_template(f"stepca/{name}.tpl.j2").render(
        cert_country="US", cert_province="S", cert_city="C", cert_org="Test", cert_ou="IT",
        hostname_stepca=f"ca.{DOMAIN}", domain=DOMAIN))

sys.path.insert(0, f"{W}/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.paths import CERT_RENEWAL_FILE, REVOKED_CERTS_FILE  # noqa: E402
from fabriclib.deploy.renew_landing_cert import renew_landing_cert  # noqa: E402
from fabriclib.pki.common.cert_names import cert_names  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
from fabriclib.setup import mint_service_certs  # noqa: E402
from fabriclib.setup import renew_service_certs as rsc  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.init_pki import _configure_ca_json  # noqa: E402

V = {"deploy_base_dir": W, "domain": DOMAIN, "hostname": "fab", "host_ip": IP, "ad_domain": f"ad.{DOMAIN}",
     "hostname_bind9": f"dns.{DOMAIN}", "hostname_stepca": f"ca.{DOMAIN}", "hostname_landing": f"info.{DOMAIN}",
     "hostname_openbao": f"vault.{DOMAIN}", "hostname_dc": f"fab.ad.{DOMAIN}", "stepca_port": 9000,
     "cert_service_days": 47, "cert_renew_after_days": 30, "cert_acme_lifetime_hours": "1128h",
     "stepca_cert_max_lifetime_hours": "1128h",
     "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}},
     "dns": {"dynamic_zone_var": {"zone_authority": True,
                                  "A": [{"name": "fab", "ip": IP}, {"name": "@", "ip": IP},
                                        {"name": "printer", "ip": "192.168.7.80"}],
                                  "CNAME": [{"name": "info", "canonical": "fab"}, {"name": "ca", "canonical": "fab"},
                                            {"name": "nas", "canonical": "printer"}]}}}
_configure_ca_json(f"{data}/config/ca.json", V)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
sh(["docker", "run", "-d", "--name", "step-ca", "--label", LABEL, "--network", "none", "-v", f"{data}:/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", IMAGE, "/usr/local/bin/step-ca", "/home/step/config/ca.json",
    "--password-file", "/home/step/secrets/password"])
for _ in range(30):
    time.sleep(1)
    if sh(["docker", "exec", "step-ca", "step", "ca", "health", "--ca-url", "https://127.0.0.1:9000", "--root",
           "/home/step/certs/root_ca.crt"], ok=False).stdout.strip() == "ok":
        break

LAND = f"{W}/nginx/certs/info.{DOMAIN}/fullchain.pem"
PATHS = {"base": W}
CRL = f"{W}/nginx/www/certs/crl/intermediate.pem"
ROOT, INTER = f"{data}/certs/root_ca.crt", f"{data}/certs/intermediate_ca.crt"


def save(v):
    with open(f"{W}/fabric/config/vars.yaml", "w") as f:
        yaml.safe_dump(v, f)


def serial():
    return describe_cert(open(LAND).read())["serial"]


def revoked():
    if not os.path.exists(REVOKED_CERTS_FILE):
        return []
    return [json.loads(line) for line in open(REVOKED_CERTS_FILE) if line.strip()]


def crl_lists(s):
    text = sh(["openssl", "crl", "-in", CRL, "-noout", "-text"], ok=False).stdout.upper()
    return s.replace(":", "").upper().lstrip("0") in text.replace(":", "").replace(" ", "")


def verifies_with_crl(path):
    """openssl verify against the published CRLs (the intermediate's, and the root's: step ca init keeps both keys)."""
    root_crl = f"{W}/nginx/www/certs/crl/root.pem"
    crls = ["-CRLfile", CRL] + (["-CRLfile", root_crl] if os.path.exists(root_crl) else [])
    return sh(["openssl", "verify", "-crl_check", "-CAfile", ROOT, "-untrusted", INTER, *crls, path],
              ok=False).returncode == 0


rsc.pick_up_cert = lambda unit: "reloaded"          # no nginx runs here: what it would do is recorded, not done

# ---------------------------------------------------------------- before the first certificate
save(V)
# covers: setting:hostname_landing -
check("negative: an apply before setup's `certs` step issues nothing (the first certificate is setup's)",
      renew_landing_cert(PATHS, V) is False and not os.path.exists(LAND))

# ---------------------------------------------------------------- setup's certs step
ctx = SetupContext(deploy_base=W, vars=json.loads(json.dumps(V)))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    mint_service_certs.run(ctx)
names = cert_names(LAND)
# covers: setting:hostname_landing +
check("setup issues the landing certificate for the host's own name, <domain> and the info alias, CN the host's",
      names == {f"fab.{DOMAIN}", DOMAIN, f"info.{DOMAIN}"}
      and f"CN=fab.{DOMAIN}" in describe_cert(open(LAND).read())["subject"].split(","),
      (names, describe_cert(open(LAND).read())["subject"]))
check("negative: a record pointing at another machine (nas -> printer) and fabric's own ca are not on it",
      names is not None and f"nas.{DOMAIN}" not in names and f"ca.{DOMAIN}" not in names, names)
first = serial()
OLD = f"{W}/replaced.pem"
shutil.copy(LAND, OLD)

# ---------------------------------------------------------------- an apply with nothing changed
check("negative: an apply whose landing names are current issues nothing and revokes nothing",
      renew_landing_cert(PATHS, V) is False and serial() == first and revoked() == [], revoked())

# ---------------------------------------------------------------- the info alias renamed to welcome
V2 = json.loads(json.dumps(V))
V2["dns"]["dynamic_zone_var"]["CNAME"][0] = {"name": "welcome", "canonical": "fab"}
save(V2)
out = io.StringIO()
with contextlib.redirect_stdout(out):
    done = renew_landing_cert(PATHS, V2)
names = cert_names(LAND)
check("the apply after a rename issues the certificate again at once, for welcome and without info",
      done is True and names == {f"fab.{DOMAIN}", DOMAIN, f"welcome.{DOMAIN}"} and serial() != first,
      (names, out.getvalue()[-800:]))
# revised 2026-10-12 by the owner (2.1.4.8): the replaced certificate is not revoked, it expires
check("...and does not revoke the one it replaced: nothing in the revocation record",
      revoked() == [], revoked())
check("...nor in the published CRL: checked against it, the old one still verifies, and so does the new one",
      os.path.exists(CRL) and not crl_lists(first) and verifies_with_crl(OLD) and verifies_with_crl(LAND),
      (first, sh(["openssl", "crl", "-in", CRL, "-noout", "-text"], ok=False).stdout[-600:]))
record = json.load(open(CERT_RENEWAL_FILE))
check("...the renewal record says it went well, nginx took the new certificate",
      record["ok"] and record["services"].get("nginx") == "reloaded", record)

# ---------------------------------------------------------------- the alias repointed at another machine
V3 = json.loads(json.dumps(V2))
V3["dns"]["dynamic_zone_var"]["CNAME"][0] = {"name": "welcome", "canonical": "printer"}
save(V3)
second = serial()
with contextlib.redirect_stdout(io.StringIO()):
    done = renew_landing_cert(PATHS, V3)
names = cert_names(LAND)
check("negative: an alias repointed at another machine leaves the certificate at the next apply (fabric's names only)",
      done is True and names == {f"fab.{DOMAIN}", DOMAIN} and serial() != second and revoked() == [], names)

# ---------------------------------------------------------------- the CA down: the apply fails loudly
V4 = json.loads(json.dumps(V3))
V4["dns"]["dynamic_zone_var"]["CNAME"][0] = {"name": "hello", "canonical": "fab"}
save(V4)
third = serial()
sh(["docker", "stop", "step-ca"], ok=False)
refusal = ""
with contextlib.redirect_stdout(io.StringIO()):
    try:
        renew_landing_cert(PATHS, V4)
    except ValidationError as e:
        refusal = str(e)
check("negative: names changed but the CA cannot issue: the apply fails, saying so; the certificate is unchanged",
      "could not be issued again" in refusal and serial() == third, refusal)
record = json.load(open(CERT_RENEWAL_FILE))
check("...and the renewal record holds the failure for status and doctor", not record["ok"] and record["error"],
      record)

cleanup()
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
