#!/usr/bin/env python3
"""Federation site CAs (manual 1.9, M2) against the real Step-CA image: a joining site makes
its key and request (make_site_ca_request), the root site signs it with its root key (sign_site_ca),
the site checks and stages the answer (stage_site_ca), and a Step-CA started the way setup's
bring-your-own-CA path starts it serves with that intermediate. Includes what must be refused.

    sudo python3 tests/pki/site_ca.py          (needs Docker, openssl, root; run by tests/pki/run.py)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

import jinja2

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
SITECA = testrun.name("sitecatest")      # per run (manual 3.1.2.6)
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki-site-ca"
IMAGE = os.environ.get("FABRIC_STEP_IMAGE") or subprocess.run(
    [sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
    capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(cmd, data=None, ok=True):
    res = subprocess.run(cmd, input=data, capture_output=True, text=True)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stderr}")
    return res


def step(home, *args, ok=True):
    return sh(["docker", "run", "--rm", "--network", "none", "-v", f"{home}:/home/step", "-e", "STEPPATH=/home/step",
               "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, *args], ok=ok)


def refused(fn, *args, match="", **kw):
    try:
        fn(*args, **kw)
    except ValidationError as exc:
        if match.lower() in str(exc).lower():
            return True
        print(f"    refused, but not for {match!r}: {exc}")
    return False


# ---------------------------------------------------------------- the root site (hq): its own root CA
shutil.rmtree(W, ignore_errors=True)
root_data = f"{W}/hq/stepca/data"
for d in ("certs", "secrets", "artifacts"):
    os.makedirs(f"{root_data}/{d}")
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)    # the installed tree
os.makedirs(f"{W}/fabric/config")
with open(f"{root_data}/secrets/password", "w") as f:
    f.write("Root-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/hq"])
step(root_data, "certificate", "create", "Fabric Test Root CA", "/home/step/certs/root_ca.crt",
     "/home/step/secrets/root_ca_key", "--profile", "root-ca", "--password-file", "/home/step/secrets/password")
ROOT = f"{root_data}/certs/root_ca.crt"
ROOT_PEM = open(ROOT).read()

sys.path.insert(0, f"{W}/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
from fabriclib.pki.make_site_ca_request import make_site_ca_request  # noqa: E402
from fabriclib.pki.sign_site_ca import _hours_left, sign_site_ca  # noqa: E402
from fabriclib.pki.stage_site_ca import stage_site_ca  # noqa: E402
from fabriclib.pki.mint_offline_cert import mint_offline_cert  # noqa: E402
from fabriclib.setup.init_pki import _configure_ca_json, _single_intermediate  # noqa: E402

USERS = {"step": {"uid": STEP_UID, "gid": STEP_UID}}
HQ = {"deploy_base_dir": f"{W}/hq", "image_stepca": IMAGE, "service_users": USERS, "site_name": "hq",
      "cert_intermediate_days": 1095}
SITE = {"image_stepca": IMAGE, "service_users": USERS}
JOIN = f"{W}/branch1/join"

# ---------------------------------------------------------------- the joining site's request
req = make_site_ca_request(SITE, "branch1", "Site-Pw-1", JOIN)
key_head = open(req["key_path"]).read(60)
check("site request: CSR made, CN '<site> Intermediate CA'",
      "BEGIN CERTIFICATE REQUEST" in req["csr"]
      and "CN=branch1 Intermediate CA" in sh(["openssl", "req", "-noout", "-subject", "-nameopt", "RFC2253"],
                                             req["csr"]).stdout, req)
check("site request: the key stays here, encrypted, 0600",
      "ENCRYPTED" in key_head and oct(os.stat(req["key_path"]).st_mode & 0o777) == "0o600", key_head)
check("site request: a retry keeps the same key and request",
      make_site_ca_request(SITE, "branch1", "Site-Pw-1", JOIN)["csr"] == req["csr"])
check("site request: invalid site name refused",
      refused(make_site_ca_request, SITE, "Bad_Name", "x", f"{W}/bad", match="invalid site name"))
check("site request: missing password refused",
      refused(make_site_ca_request, SITE, "branch9", "", f"{W}/bad", match="password is missing"))

# ---------------------------------------------------------------- the root signs it
signed = sign_site_ca(HQ, "alice", "branch1", req["csr"])
text = sh(["openssl", "x509", "-noout", "-text"], signed["cert"]).stdout
check("sign: a CA with path length 0, issued by the root",
      "CA:TRUE, pathlen:0" in text and signed["info"]["issuer"] == describe_cert(ROOT_PEM)["subject"], text[:600])
check("sign: certificate and CRL signing only", "Certificate Sign, CRL Sign" in text, text[:800])
check("sign: subject is the site's CA name, no other names",
      signed["info"]["subject"] == "CN=branch1 Intermediate CA" and not signed["info"]["sans"], signed["info"])
check("sign: chains to the root", sh(["openssl", "verify", "-CAfile", ROOT], signed["cert"], ok=False).returncode == 0)
check("sign: never outlives the root",
      _hours_left(signed["info"]["not_after"]) <= _hours_left(describe_cert(ROOT_PEM)["not_after"]),
      (signed["info"]["not_after"], describe_cert(ROOT_PEM)["not_after"]))
ledger = [json.loads(line) for line in open(f"{W}/fabric/archive/issued-certs.jsonl")]
check("sign: recorded in the issued ledger (never a key)",
      any(e.get("kind") == "site-ca" and e.get("device") == "branch1" for e in ledger)
      and "PRIVATE" not in open(f"{W}/fabric/archive/issued-certs.jsonl").read(), ledger)

check("sign: this site's own name refused", refused(sign_site_ca, HQ, "alice", "hq", req["csr"], match="own name"))
check("sign: invalid site name refused", refused(sign_site_ca, HQ, "alice", "../x", req["csr"], match="invalid site"))
check("sign: a request for another site's name refused",
      refused(sign_site_ca, HQ, "alice", "branch2", req["csr"], match="names only CN"))
other = tempfile.mkdtemp(dir=W)
sh(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
    f"{other}/k", "-out", f"{other}/r", "-subj", "/CN=branch3 Intermediate CA", "-addext", "subjectAltName=DNS:evil.test"])
check("sign: a request with extra names refused",
      refused(sign_site_ca, HQ, "alice", "branch3", open(f"{other}/r").read(), match="names only CN"))
sh(["openssl", "req", "-new", "-newkey", "rsa:1024", "-nodes", "-keyout", f"{other}/k2", "-out", f"{other}/r2",
    "-subj", "/CN=branch4 Intermediate CA"])
check("sign: a weak key refused", refused(sign_site_ca, HQ, "alice", "branch4", open(f"{other}/r2").read(),
                                          match="too small"))
check("sign: a byoc root without its key refused",
      refused(sign_site_ca, dict(HQ, byoc=True), "alice", "branch1", req["csr"], match="not on this host"))
shutil.copy(f"{root_data}/secrets/root_ca_key", f"{other}/root.key")
shutil.copy(f"{root_data}/secrets/password", f"{other}/root.pw")
byoc = sign_site_ca(dict(HQ, byoc=True), "alice", "branch1", req["csr"], root_key=f"{other}/root.key",
                    root_password_file=f"{other}/root.pw")
check("sign: a byoc root signs with the root key brought in",
      sh(["openssl", "verify", "-CAfile", ROOT], byoc["cert"], ok=False).returncode == 0)
with open(f"{other}/wrong.pw", "w") as f:
    f.write("not-the-password")
check("sign: the wrong root password refused",
      refused(sign_site_ca, dict(HQ, byoc=True), "alice", "branch1", req["csr"], root_key=f"{other}/root.key",
              root_password_file=f"{other}/wrong.pw", match="step-ca refused"))
check("sign: nothing left in the artifacts directory", os.listdir(f"{root_data}/artifacts") == [],
      os.listdir(f"{root_data}/artifacts"))

# ---------------------------------------------------------------- the site checks and stages the answer
fp = describe_cert(ROOT_PEM)["sha256"]
wrong = ("AB:" if fp.startswith("AA:") else "AA:") + fp[3:]   # never the real one (1 run in 256 it was: 2.3.1.32)
check("stage: a root other than the invitation's refused",
      refused(stage_site_ca, JOIN, signed["cert"], ROOT_PEM, root_sha256=wrong, match="fingerprint"))
check("stage: a certificate that does not chain refused",
      refused(stage_site_ca, JOIN, signed["cert"], signed["cert"], match="self-signed"))
req2 = make_site_ca_request(SITE, "branch2", "Site-Pw-2", f"{W}/branch2/join")
check("stage: a certificate for another site's key refused",
      refused(stage_site_ca, JOIN, sign_site_ca(HQ, "alice", "branch2", req2["csr"])["cert"], ROOT_PEM,
              match="not for this site's key"))
staged = stage_site_ca(JOIN, signed["cert"], ROOT_PEM, root_sha256=fp)
check("stage: vars for the bring-your-own-CA path",
      staged["byoc"] is True and all(os.path.isfile(staged[k]) for k in ("ca_crt_path", "ica_crt_path", "ica_key_path")),
      staged)

# ---------------------------------------------------------------- the site CA in use
pw = f"{JOIN}/leaf.pw"
with open(pw, "w") as f:
    f.write("Site-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", JOIN])
step(JOIN, "certificate", "create", "pc1.branch1.test", "/home/step/leaf.crt", "/home/step/leaf.key",
     "--profile", "leaf", "--ca", "/home/step/site_ca.crt", "--ca-key", "/home/step/site_ca_key",
     "--ca-password-file", "/home/step/leaf.pw", "--no-password", "--insecure", "--san", "pc1.branch1.test")
check("use: a leaf from the site CA verifies against the root",
      sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", f"{JOIN}/site_ca.crt", f"{JOIN}/leaf.crt"],
         ok=False).returncode == 0)
rogue = step(JOIN, "certificate", "create", "Rogue CA", "/home/step/rogue.crt", "/home/step/rogue.key",
             "--profile", "intermediate-ca", "--ca", "/home/step/site_ca.crt", "--ca-key", "/home/step/site_ca_key",
             "--ca-password-file", "/home/step/leaf.pw", "--no-password", "--insecure", ok=False)
if rogue.returncode == 0:      # step made it anyway: whoever verifies must refuse it
    step(JOIN, "certificate", "create", "x.test", "/home/step/x.crt", "/home/step/x.key", "--profile", "leaf",
         "--ca", "/home/step/rogue.crt", "--ca-key", "/home/step/rogue.key", "--no-password", "--insecure",
         "--san", "x.test")
    chain = f"{JOIN}/chain.pem"
    with open(chain, "w") as f:
        f.write(open(f"{JOIN}/site_ca.crt").read() + open(f"{JOIN}/rogue.crt").read())
    v = sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", chain, f"{JOIN}/x.crt"], ok=False)
    check("use: a CA made by a site CA is not trusted (path length 0)", v.returncode != 0, v.stdout)
else:
    check("use: a site CA cannot make another CA (path length 0)", True)

# Step-CA started the way setup's bring-your-own-CA path leaves it (init_pki, byoc)
data = f"{W}/branch1/stepca/data"
os.makedirs(f"{data}/secrets")
with open(f"{data}/secrets/password", "w") as f:
    f.write("Site-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/branch1/stepca"])
step(data, "ca", "init", "--name=branch1", "--dns=ca.branch1.test,localhost", "--address=:9000",
     "--provisioner=admin", "--password-file=/home/step/secrets/password",
     "--provisioner-password-file=/home/step/secrets/password")
shutil.copy2(staged["ca_crt_path"], f"{data}/certs/root_ca.crt")
with open(f"{data}/certs/intermediate_ca.crt", "w") as out:      # the layout earlier byoc installs had
    out.write(open(staged["ica_crt_path"]).read() + open(staged["ca_crt_path"]).read())
check("byoc: an intermediate_ca.crt carrying the root is converged to the intermediate alone, once",
      _single_intermediate(f"{data}/certs/intermediate_ca.crt") is True
      and open(f"{data}/certs/intermediate_ca.crt").read().count("BEGIN CERTIFICATE") == 1
      and _single_intermediate(f"{data}/certs/intermediate_ca.crt") is False)
shutil.copy2(staged["ica_key_path"], f"{data}/secrets/intermediate_ca_key")
os.remove(f"{data}/secrets/root_ca_key")
shutil.copy2(f"{data}/certs/intermediate_ca.crt", f"{data}/certs/intermediate_chain.crt")   # a flat site: no parents
_configure_ca_json(f"{data}/config/ca.json", {"byoc": True, "hostname_stepca": "ca.branch1.test"})
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
testrun.remove("container", SITECA)      # this run's only
sh(["docker", "run", "-d", "--name", SITECA, *testrun.labels(), "-v", f"{data}:/home/step", "--user", f"{STEP_UID}:{STEP_UID}",
    IMAGE, "/usr/local/bin/step-ca", "/home/step/config/ca.json", "--password-file", "/home/step/secrets/password"])
health = None
for _ in range(20):
    time.sleep(2)
    health = sh(["docker", "exec", SITECA, "step", "ca", "health", "--ca-url", "https://localhost:9000",
                 "--root", "/home/step/certs/root_ca.crt"], ok=False)
    if health.stdout.strip() == "ok":
        break
check("use: Step-CA serves with the site's encrypted intermediate key", health.stdout.strip() == "ok",
      sh(["docker", "logs", SITECA], ok=False).stderr[-400:])
roots = sh(["docker", "exec", SITECA, "step", "ca", "roots", "--ca-url", "https://localhost:9000",
            "--root", "/home/step/certs/root_ca.crt"], ok=False).stdout
check("use: the site's Step-CA hands out the organisation's root", roots.strip() == ROOT_PEM.strip(), roots[:200])
testrun.remove("container", SITECA)      # this run's only

# offline signing with the site's intermediate (setup's admin client certificate, extra certs, the PKI page):
# what failed on a real joined site while intermediate_ca.crt carried the root
os.makedirs(f"{data}/templates/certs", exist_ok=True)
with open(f"{data}/templates/certs/leaf.tpl", "w") as f:
    f.write(jinja2.Environment().from_string(open(f"{REPO}/templates/stepca/leaf.tpl.j2").read()).render(
        cert_country="US", cert_province="CA", cert_city="Test", cert_org="Fabric Test", cert_ou="IT"))
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
crt, key = mint_offline_cert({"deploy_base_dir": f"{W}/branch1", "image_stepca": IMAGE, "service_users": USERS},
                             "pc2.branch1.test", days=30, kty="EC", crv="P-256")
check("use: offline signing with the site's intermediate (encrypted key) verifies against the root",
      sh(["openssl", "verify", "-CAfile", ROOT, "-untrusted", f"{data}/certs/intermediate_ca.crt", crt],
         ok=False).returncode == 0)

print(json.dumps({"failed": FAILED}))
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
