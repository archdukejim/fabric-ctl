#!/usr/bin/env python3
"""Certificate revocation (manual 2.1.5.10), without containers: a root and an intermediate laid out as an install's
(keys encrypted, as Step-CA's), leaves in the issued-certificate ledger; revoking by name and by serial, the CRLs
(openssl verify -crl_check refuses the revoked certificate and accepts the others), what nginx and FreeRADIUS are
given, the issued list's state, `fabricctl certs`' revoke and issued, and every refusal.

    python3 tests/pki/revocation.py            (openssl; no Docker, no root)
"""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.pki import revoke_cert as rc  # noqa: E402
from fabriclib.pki import run_certs_command as rcc  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
from fabriclib.pki.list_issued import list_issued  # noqa: E402
from fabriclib.pki.publish_crl import publish_crl  # noqa: E402

FAILED = 0
W = tempfile.mkdtemp()
BASE = os.path.join(W, "opt")
CERTS = os.path.join(BASE, "stepca", "data", "certs")
SECRETS = os.path.join(BASE, "stepca", "data", "secrets")
LEDGER = os.path.join(W, "issued.jsonl")
REVOKED = os.path.join(W, "revoked.jsonl")
for d in (CERTS, SECRETS, os.path.join(BASE, "nginx", "certs", "client-ca"), os.path.join(BASE, "freeradius", "certs")):
    os.makedirs(d)
PW = os.path.join(SECRETS, "password")
open(PW, "w").write("test-ca-password\n")


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def sh(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def key(path):
    sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-aes256",
       "-pass", f"file:{PW}", "-out", path)


def ext(name, body):
    path = os.path.join(W, f"{name}.ext")
    open(path, "w").write(body)
    return path


key(os.path.join(SECRETS, "root_ca_key"))
sh("openssl", "req", "-x509", "-key", os.path.join(SECRETS, "root_ca_key"), "-passin", f"file:{PW}", "-days", "3650",
   "-subj", "/CN=Test Root CA", "-out", os.path.join(CERTS, "root_ca.crt"),
   "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
CA_EXT = ext("ca", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")


def signed(name, issuer_cert, issuer_key, extfile, newkey=None):
    k = newkey or os.path.join(W, f"{name}.key")
    if not newkey:
        sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", k)
    csr = os.path.join(W, f"{name}.csr")
    sh("openssl", "req", "-new", "-key", k, "-subj", f"/CN={name}", "-out", csr,
       *(["-passin", f"file:{PW}"] if newkey else []))
    crt = os.path.join(W, f"{name}.crt")
    sh("openssl", "x509", "-req", "-in", csr, "-CA", issuer_cert, "-CAkey", issuer_key, "-passin", f"file:{PW}",
       "-CAcreateserial", "-days", "365", "-out", crt, "-extfile", extfile)
    return crt


key(os.path.join(SECRETS, "intermediate_ca_key"))
inter = signed("Test Intermediate CA", os.path.join(CERTS, "root_ca.crt"), os.path.join(SECRETS, "root_ca_key"),
               CA_EXT, newkey=os.path.join(SECRETS, "intermediate_ca_key"))
subprocess.run(["cp", inter, os.path.join(CERTS, "intermediate_ca.crt")], check=True)
LEAF = ext("leaf", "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n")
site_ca = signed("lab Intermediate CA", os.path.join(CERTS, "root_ca.crt"), os.path.join(SECRETS, "root_ca_key"),
                 CA_EXT)
leaves = {n: signed(n, inter, os.path.join(SECRETS, "intermediate_ca_key"), LEAF)
          for n in ("laptop-1", "laptop-2", "printer", "printer-old")}
for kind, path in [("client", leaves["laptop-1"]), ("keypair", leaves["laptop-2"]), ("csr", leaves["printer"]),
                   ("csr", leaves["printer-old"]), ("site-ca", site_ca)]:
    info = describe_cert(open(path).read())
    if path == leaves["printer-old"]:                  # two certificates named "printer"
        info["subject"] = info["subject"].replace("printer-old", "printer")
    with open(LEDGER, "a") as f:
        f.write(json.dumps({"when": "2026-10-08T10:00:00", "actor": "test", "source": "cli", "kind": kind,
                            **{k: info.get(k) for k in ("subject", "issuer", "sans", "serial", "not_after",
                                                        "sha256", "key")}}) + "\n")
V = {"deploy_base_dir": BASE, "service_users": {}}
picked = []
rc.pick_up_cert = lambda unit: picked.append(unit) or "reloaded"
rc.write_audit = lambda *a, **k: None


def verify(cert):
    """openssl verify with the published CRLs (every level of the chain)."""
    chain = os.path.join(W, "chain.pem")
    open(chain, "w").write(open(os.path.join(CERTS, "root_ca.crt")).read()
                           + open(os.path.join(CERTS, "intermediate_ca.crt")).read())
    crls = os.path.join(BASE, "nginx", "certs", "client-ca", "crl.pem")
    res = subprocess.run(["openssl", "verify", "-crl_check_all", "-CAfile", chain, "-CRLfile", crls, cert],
                         capture_output=True, text=True)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def revoke(target, reason="unspecified"):
    try:
        return rc.revoke_cert(V, "test", target, reason, ledger=LEDGER, revoked=REVOKED)
    except ValidationError as e:
        return str(e)


print("--- publishing before anything is revoked")
res = publish_crl(V, revoked_file=REVOKED, fetch_sites=False)
check("CRLs published: the intermediate's and the root's (its key is here); nginx and FreeRADIUS given them",
      res["root"] and all(os.path.exists(os.path.join(BASE, "nginx", "www", "certs", "crl", f)) for f in
                          ("intermediate.crl", "intermediate.pem", "root.crl", "root.pem"))
      and "ssl_crl" in open(os.path.join(BASE, "nginx", "config", "conf.d", "client-crl.inc")).read()
      and open(os.path.join(BASE, "freeradius", "certs", "ca.pem")).read().count("BEGIN X509 CRL") == 1, res)
check("every certificate verifies against the empty CRLs", all(verify(c)[0] for c in leaves.values()),
      [verify(c) for c in leaves.values()])

print("--- revoking")
done = revoke("laptop-1", "keyCompromise")
ok_now, why = verify(leaves["laptop-1"])
check("by name: recorded, CRLs republished, nginx and FreeRADIUS picking it up; openssl now refuses it",
      isinstance(done, dict) and done["reason"] == "keyCompromise" and not ok_now and "revoked" in why
      and {"nginx", "freeradius"} <= set(picked), (done, why, picked))
check("the others still verify", verify(leaves["laptop-2"])[0] and verify(leaves["printer"])[0])
serial = describe_cert(open(leaves["laptop-2"]).read())["serial"]
colons = ":".join(serial[i:i + 2] for i in range(0, len(serial), 2))
done = revoke(colons)
check("by serial (with colons): revoked, refused by openssl", isinstance(done, dict) and not verify(leaves["laptop-2"])[0],
      done)
done = revoke("lab Intermediate CA", "cessationOfOperation")
root_crl = sh("openssl", "crl", "-in", os.path.join(BASE, "nginx", "www", "certs", "crl", "root.pem"), "-noout", "-text")
check("a site CA the root signed goes into the root's CRL, not the intermediate's",
      isinstance(done, dict) and done["issuer"] == "root"
      and describe_cert(open(site_ca).read())["serial"] in root_crl.replace(":", "").upper(), (done, root_crl[-300:]))
states = {r["subject"].split("CN=")[-1]: r["status"] for r in list_issued(path=LEDGER, revoked=REVOKED)}
check("the issued list shows them revoked, the rest valid", states.get("laptop-1") == states.get("laptop-2") ==
      states.get("lab Intermediate CA") == "revoked" and states.get("printer") == "valid", states)

print("--- refusals")
check("negative: an unknown reason", "unknown reason" in revoke("printer-x", "because"))
check("negative: a name not in the ledger, saying to give the serial", "give its serial" in revoke("no-such-host"))
check("negative: two certificates of that name: give the serial, listing them", "2 certificates are named" in
      revoke("printer"))
check("negative: already revoked", "already revoked" in revoke("laptop-1"))
os.rename(os.path.join(SECRETS, "root_ca_key"), os.path.join(W, "away"))
open(LEDGER, "a").write(json.dumps({"kind": "site-ca", "subject": "CN=other Intermediate CA", "serial": "ABCDEF",
                                    "issuer": "CN=Test Root CA", "not_after": "Oct  8 10:00:00 2030 GMT"}) + "\n")
check("negative: a root-signed site CA on a host without the root key (a brought-in root)",
      "not on this host" in revoke("other Intermediate CA"))
res = publish_crl(V, revoked_file=REVOKED, fetch_sites=False)
check("without the root key: no root CRL, and the web console checks none (nginx needs every level)",
      not res["root"] and "ssl_crl" not in open(os.path.join(BASE, "nginx", "config", "conf.d",
                                                              "client-crl.inc")).read(), res)
os.rename(os.path.join(W, "away"), os.path.join(SECRETS, "root_ca_key"))

print("--- fabricctl certs revoke / issued")


class Ctx:
    def load_state(self):
        self.vars = V
        return self


rcc.revoke_cert = lambda v, actor, target, reason, source: rc.revoke_cert(v, actor, target, reason, source,
                                                                          ledger=LEDGER, revoked=REVOKED)
rcc.list_issued = lambda limit: list_issued(limit=limit, path=LEDGER, revoked=REVOKED)
for argv, code, text in ((["revoke"], 2, "usage"), (["revoke", "a", "b"], 2, "usage"),
                         (["revoke", "printer", "--reason"], 2, "usage"), (["bogus"], 2, "usage"),
                         (["revoke", "no-such-host"], 1, "give its serial"), (["issued"], 0, "revoked")):
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        got = rcc.run_certs_command(Ctx(), argv)
    # covers: cli:certs +-
    check(f"fabricctl certs {' '.join(argv)}: exit {code}" + (" (refused)" if code else ""),
          got == code and text in (err.getvalue() + out.getvalue()), (got, err.getvalue()[-200:]))
pr = describe_cert(open(leaves["printer"]).read())["serial"]
with contextlib.redirect_stdout(io.StringIO()) as out:
    got = rcc.run_certs_command(Ctx(), ["revoke", pr, "--reason", "superseded"])
# covers: cli:certs +
check("fabricctl certs revoke <serial> --reason superseded: done, refused by openssl",
      got == 0 and "revoked" in out.getvalue() and not verify(leaves["printer"])[0], out.getvalue())

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
