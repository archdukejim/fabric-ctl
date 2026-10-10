#!/usr/bin/env python3
"""ACME from fabric's CA for machines on the LAN (manual 2.1.5.8), against the real Step-CA image: a CA made by
`step ca init` and configured by fabric's own init_pki._configure_ca_json (the ACME provisioner, its 47-day lifetime,
fabric's ACME template: names under the domain only, its CRL distribution point); a LAN
machine's ACME client (the step CLI, http-01 on port 80 under its own name) gets a certificate; and the refusals: a
name outside the domain, an address, a name the client does not answer for.

    sudo python3 tests/pki/acme.py          (needs Docker, root)
"""
import contextlib
import io
import os
import shutil
import subprocess
import sys
import time

import jinja2

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.pki import run_acme_command as rac  # noqa: E402
from fabriclib.setup.init_pki import _configure_ca_json  # noqa: E402

W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki-acme"
IMAGE = os.environ.get("FABRIC_STEP_IMAGE") or subprocess.run(
    [sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "stepca"],
    capture_output=True, text=True, check=True).stdout.strip()
STEP_UID = 1912
NET, DOMAIN = "fabric-acme-test", "lan.test"
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
    sh(["docker", "rm", "-f", "acme-ca", "acme-machine"], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


cleanup()
shutil.rmtree(W, ignore_errors=True)
data = f"{W}/stepca/data"
os.makedirs(f"{data}/secrets")
os.makedirs(f"{data}/templates/certs")
open(f"{data}/secrets/password", "w").write("Acme-Test-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/stepca"])
sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", IMAGE, "ca", "init", "--name=acme-test",
    f"--dns=ca.{DOMAIN},localhost", "--address=:9000", "--provisioner=admin",
    "--password-file=/home/step/secrets/password", "--provisioner-password-file=/home/step/secrets/password"])
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(REPO, "templates")))
for name in ("leaf", "acme"):                       # fabric's templates, rendered as setup renders them
    open(f"{data}/templates/certs/{name}.tpl", "w").write(env.get_template(f"stepca/{name}.tpl.j2").render(
        cert_country="US", cert_province="S", cert_city="C", cert_org="Test", cert_ou="IT",
        hostname_certs=f"certs.{DOMAIN}", domain=DOMAIN))
v = {"hostname_stepca": f"ca.{DOMAIN}", "domain": DOMAIN, "cert_acme_lifetime_hours": "1128h",
     "stepca_cert_max_lifetime_hours": "1128h"}
check("fabric's converge writes the ACME provisioner (changed), and a second run changes nothing",
      _configure_ca_json(f"{data}/config/ca.json", v) is True and _configure_ca_json(f"{data}/config/ca.json", v) is False)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
sh(["docker", "network", "create", NET])
sh(["docker", "run", "-d", "--name", "acme-ca", "--network", NET, "--network-alias", f"ca.{DOMAIN}", "-v",
    f"{data}:/home/step", "--user", f"{STEP_UID}:{STEP_UID}", IMAGE, "/usr/local/bin/step-ca",
    "/home/step/config/ca.json", "--password-file", "/home/step/secrets/password"])
for _ in range(30):
    time.sleep(1)
    if sh(["docker", "exec", "acme-ca", "step", "ca", "health", "--ca-url", "https://localhost:9000", "--root",
           "/home/step/certs/root_ca.crt"], ok=False).stdout.strip() == "ok":
        break
# the LAN machine: its own container, reachable by its name on the network, as root so its client can listen on 80
sh(["docker", "run", "-d", "--name", "acme-machine", "--network", NET, "--network-alias", f"nas.{DOMAIN}",
    "--network-alias", "nas.example.org",          # it answers for a name outside the domain too: the policy must refuse
    "--user", "0:0", "-v", f"{data}/certs/root_ca.crt:/root_ca.crt:ro", "--entrypoint", "sleep", IMAGE, "600"])


def get(name, *extra):
    """The machine asks for a certificate for name over ACME (http-01, its own port 80)."""
    return sh(["docker", "exec", "acme-machine", "step", "ca", "certificate", name, f"/tmp/{name}.crt",
               f"/tmp/{name}.key", "--provisioner", "acme", "--ca-url", f"https://ca.{DOMAIN}:9000",
               "--root", "/root_ca.crt", "--standalone", "--http-listen", ":80", "--force", *extra], ok=False)


res = get(f"nas.{DOMAIN}")
cert = sh(["docker", "exec", "acme-machine", "cat", f"/tmp/nas.{DOMAIN}.crt"], ok=False).stdout
text = subprocess.run(["openssl", "x509", "-noout", "-text", "-dates"], input=cert, capture_output=True,
                      text=True).stdout
check("http-01: the machine gets a certificate for its own name under the domain",
      res.returncode == 0 and "BEGIN CERTIFICATE" in cert, res.stderr[-400:])
dates = dict(line.split("=", 1) for line in text.splitlines() if line.startswith(("notBefore", "notAfter")))
hours = None
if dates:
    import datetime
    fmt = "%b %d %H:%M:%S %Y %Z"
    hours = (datetime.datetime.strptime(dates["notAfter"], fmt)
             - datetime.datetime.strptime(dates["notBefore"], fmt)).total_seconds() / 3600
check("…for 47 days (1128 h, within a minute of Step-CA's backdating), naming the CRL (fabric's leaf template)",
      hours is not None and 1128 <= hours <= 1129 and f"http://certs.{DOMAIN}/crl/intermediate.crl" in text,
      (hours, text[-600:]))
res = get("nas.example.org")
check("negative: a name outside the domain is refused by fabric's ACME template (though its challenge passes)",
      res.returncode != 0, res.stderr[-400:])
res = get("192.0.2.10")
check("negative: an address is refused (names only)", res.returncode != 0, res.stderr[-400:])
res = get(f"printer.{DOMAIN}")
check("negative: a name the machine does not answer for (http-01 cannot be checked) gets nothing",
      res.returncode != 0, res.stderr[-400:])
cleanup()

print("--- fabricctl acme")
calls = []
rac.add_tsig_key = lambda actor, entry: calls.append(("add", entry))
rac.remove_tsig_key = lambda actor, name: calls.append(("remove", name))
apply_ok = [True]
rac.apply_changes = lambda actor, source: (apply_ok[0], "apply failed: zone did not load")


class Ctx:
    def load_state(self):
        self.vars = {"domain": DOMAIN, "hostname_stepca": f"ca.{DOMAIN}", "hostname_certs": f"certs.{DOMAIN}",
                     "host_ip": "192.0.2.1", "bind_dns_port": 5053,
                     "tsig_keys": [{"name": "acme-nas", "records": ["nas"]}, {"name": "npm", "records": ["npm"]}]}
        return self


def acme(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rac.run_acme_command(Ctx(), list(argv))
    return code, out.getvalue() + err.getvalue()


code, text = acme("info")
# covers: cli:acme.info +
check("acme info: the directory, the root to trust, the names allowed, http-01 and dns-01",
      code == 0 and f"https://ca.{DOMAIN}/acme/acme/directory" in text and "port 5053" in text, text)
code, text = acme("enroll", f"nas.{DOMAIN}", "--dns")
# covers: cli:acme.enroll +
check("acme enroll <name>.<domain> --dns: a TSIG key for that name's TXT challenge only, applied",
      code == 0 and calls[-1] == ("add", {"name": "acme-nas", "records": ["nas"], "record_types": ["TXT"]})
      and "/opt/acme-nas/rfc2136.ini" in text, (calls, text))
code, text = acme("enroll", "printer")
check("acme enroll without --dns: nothing to enroll for http-01 (no key made)",
      code == 0 and "nothing to enroll" in text and len(calls) == 1, text)
code, text = acme("list")
# covers: cli:acme.list +
check("acme list: the machines with a DNS-01 key (not other TSIG keys)",
      code == 0 and "nas" in text and "npm" not in text and "1 machine(s)" in text, text)
code, text = acme("remove", "nas")
# covers: cli:acme.remove +
check("acme remove: its key withdrawn, applied", code == 0 and calls[-1] == ("remove", "acme-nas"), (calls, text))
for argv, want, what in ((("enroll", "Bad_Name", "--dns"), 1, "a name that is not a hostname"),
                         (("enroll", "nas", "--dns", "--force"), 2, "an unknown flag"),
                         (("remove", "nas", "--dns"), 2, "--dns on remove"), (("bogus",), 2, "an unknown command"),
                         (("enroll",), 2, "no name")):
    code, text = acme(*argv)
    # covers: cli:acme cli:acme.enroll cli:acme.remove -
    check(f"negative: acme {' '.join(argv)} refused ({what}), exit {want}",
          code == want and ("error:" in text or "usage:" in text), (code, text[-200:]))
apply_ok[0] = False
code, text = acme("enroll", "nas2", "--dns")
check("negative: an apply that fails is reported, exit 1", code == 1 and "apply failed" in text, text)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
