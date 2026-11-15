#!/usr/bin/env python3
"""Revoking any certificate from the console and the Lifetimes page (decisions 2.1.5.13, 2.1.5.14; manual 1.5.1.9.7,
1.5.1.10.6), against fabric's own Step-CA image built here (its certificate reader inside) running as setup runs it (a
container named step-ca): every certificate is listed (fabric's own from disk, a LAN machine's ACME one and the service
certificates from Step-CA's database through a copy, an 802.1X machine's from the ledger with its device); a LAN
machine's ACME certificate revoked through the agent's route is in the CRL and refused by openssl's CRL check; a
service certificate revoked is replaced first and nginx keeps answering with the new one; Step-CA down, nothing is
revoked; a shorter ACME lifetime set through the agent's route is the next ACME certificate's lifetime; a shorter
service lifetime renews fabric's certificates at the Apply; the refusals (a file that is not a certificate, another
CA's certificate, the CA's own, an unknown serial, the name not typed again, already revoked; lifetimes over the
intermediate's, a renewal with no run left, a default over its maximum) each leave everything unchanged; and
`fabricctl certs lifetimes`.

    sudo python3 tests/pki/console.py          (needs Docker with network for the Go modules, openssl, root;
                                                uses the container name step-ca)
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
sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402
# step-ca is the product's name (fabric's mint_cert uses it): one such run at a time (manual 3.1.2.6)
LOCK = testrun.product_names_lock("pki console").__enter__()
W = os.environ.get("FABRIC_TEST_OUT", "/tmp/fabric-tests") + "/pki-console"


def ref(name):
    return subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), name], capture_output=True,
                          text=True, check=True).stdout.strip()


UPSTREAM, GOLANG, NGINX = ref("stepca"), ref("golang"), ref("nginx")
IMAGE = testrun.name("fabric-test/stepca")
NET, MACHINE, WEB = testrun.name("fabric-console-test"), testrun.name("console-machine"), testrun.name("console-nginx")
WEB_PORT = testrun.port(18443)
STEP_UID = 1912
DOMAIN, IP = "lan.test", "192.168.7.53"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode != 0:
        raise SystemExit(f"command failed: {cmd}\n{res.stdout[-800:]}\n{res.stderr[-800:]}")
    return res


def cleanup():
    testrun.remove("container", "step-ca", MACHINE, WEB)      # this run's only
    testrun.remove("network", NET)


def healthy(seconds=60):
    for _ in range(seconds):
        time.sleep(1)
        if sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", "step-ca"], ok=False).stdout.strip() == "healthy":
            return True
    return False


cleanup()
shutil.rmtree(W, ignore_errors=True)

# ---------------------------------------------------------------- fabric's Step-CA image, with its reader
print("--- fabric's Step-CA image (packaging/images/stepca), built with the pinned Go image")
built = sh(["docker", "build", "-q", "-t", IMAGE, "--build-arg", f"BASE_IMAGE={UPSTREAM}", "--build-arg",
            f"GO_IMAGE={GOLANG}", f"{REPO}/packaging/images/stepca"], ok=False)
usage = sh(["docker", "run", "--rm", "--entrypoint", "/usr/local/bin/fabric-certlist", IMAGE], ok=False)
# covers: setting:image_golang +
check("the image builds in the pinned Go image, and carries the reader (it answers with its usage)",
      built.returncode == 0 and usage.returncode == 2 and "usage: fabric-certlist" in usage.stderr,
      (built.stderr[-600:], usage.stderr))
label = sh(["docker", "image", "inspect", "-f", '{{index .Config.Labels "org.fabric.go"}}', IMAGE], ok=False)
check("...labelled with the Go image it was built in (a host rebuilds when that changes: needs_rebuild)",
      label.stdout.strip() == GOLANG, label.stdout)
unpinned = sh(["docker", "build", "-q", "--build-arg", f"BASE_IMAGE={UPSTREAM}", f"{REPO}/packaging/images/stepca"],
              ok=False)
# covers: setting:image_golang -
check("negative: without GO_IMAGE the image does not build (no unpinned default)", unpinned.returncode != 0,
      unpinned.stdout[-300:])
if built.returncode != 0:
    cleanup()
    sys.exit(1)

# ---------------------------------------------------------------- an install's layout, a CA made by step ca init
subprocess.run(["bash", f"{REPO}/packaging/deb/assemble-tree.sh", W], check=True)   # the installed tree: INSTALL_DIR
data = f"{W}/stepca/data"
os.makedirs(f"{data}/secrets")
os.makedirs(f"{data}/templates/certs")
os.makedirs(f"{W}/fabric/config", exist_ok=True)
open(f"{data}/secrets/password", "w").write("Console-Test-Pw-1")
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", f"{W}/stepca"])
sh(["docker", "run", "--rm", "--network", "none", "-v", f"{data}:/home/step", "-e", "STEPPATH=/home/step",
    "--user", f"{STEP_UID}:{STEP_UID}", "--entrypoint", "/usr/local/bin/step", UPSTREAM, "ca", "init",
    "--name=console-test", f"--dns=ca.{DOMAIN},localhost,127.0.0.1", "--address=:9000", "--provisioner=admin",
    "--password-file=/home/step/secrets/password", "--provisioner-password-file=/home/step/secrets/password"])
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(REPO, "templates")))
for name in ("leaf", "acme"):                       # fabric's templates, rendered as setup renders them
    open(f"{data}/templates/certs/{name}.tpl", "w").write(env.get_template(f"stepca/{name}.tpl.j2").render(
        cert_country="US", cert_province="S", cert_city="C", cert_org="Test", cert_ou="IT",
        hostname_stepca=f"ca.{DOMAIN}", domain=DOMAIN))

sys.path.insert(0, f"{W}/fabric/lib")
from agent import post_pending  # noqa: E402
from agent.get_route import READS  # noqa: E402
from agent.post_pki import post_pki  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE, VARS_FILE  # noqa: E402
from fabriclib.pki import replace_service_cert as rsc_mod  # noqa: E402
from fabriclib.pki import revoke_cert as rc  # noqa: E402
from fabriclib.pki import run_certs_command as rcc  # noqa: E402
from fabriclib.pki import set_lifetimes as sl  # noqa: E402
from fabriclib.pki.ca_summary import ca_summary  # noqa: E402
from fabriclib.pki.common.describe_cert import describe_cert  # noqa: E402
from fabriclib.pki.issue_key_pair import issue_key_pair  # noqa: E402
from fabriclib.pki.list_certs import list_certs  # noqa: E402
from fabriclib.pki.list_stepca_certs import list_stepca_certs  # noqa: E402
from fabriclib.pki.read_lifetimes import read_lifetimes  # noqa: E402
from fabriclib.setup import mint_service_certs  # noqa: E402
from fabriclib.setup import renew_service_certs as renew_mod  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.init_pki import _configure_ca_json  # noqa: E402

V = {"deploy_base_dir": W, "domain": DOMAIN, "hostname": "fab", "host_ip": IP, "ad_domain": f"ad.{DOMAIN}",
     "hostname_bind9": f"dns.{DOMAIN}", "hostname_stepca": f"ca.{DOMAIN}", "hostname_landing": f"info.{DOMAIN}",
     "hostname_openbao": f"vault.{DOMAIN}", "hostname_dc": f"fab.ad.{DOMAIN}", "stepca_port": 9000,
     "cert_service_days": 47, "cert_renew_after_days": 30, "cert_acme_lifetime_hours": "1128h",
     "pki_manual_default_days": 365, "pki_manual_max_days": 1825, "stepca_cert_max_lifetime_hours": "43800h",
     "image_stepca": UPSTREAM, "service_users": {"step": {"uid": STEP_UID, "gid": STEP_UID}},
     "dns": {"dynamic_zone_var": {"zone_authority": True, "A": [{"name": "fab", "ip": IP}, {"name": "@", "ip": IP}],
                                  "CNAME": [{"name": "info", "canonical": "fab"}]}}}


def save(v):
    with open(VARS_FILE, "w") as f:
        yaml.safe_dump(v, f)


def settings():
    return open(VARS_FILE).read()


def revoked():
    if not os.path.exists(REVOKED_CERTS_FILE):
        return []
    return [json.loads(line) for line in open(REVOKED_CERTS_FILE) if line.strip()]


ROOT, INTER = f"{data}/certs/root_ca.crt", f"{data}/certs/intermediate_ca.crt"
CRL = f"{W}/nginx/www/certs/crl/intermediate.pem"


def verifies_with_crl(path):
    root_crl = f"{W}/nginx/www/certs/crl/root.pem"
    crls = ["-CRLfile", CRL] + (["-CRLfile", root_crl] if os.path.exists(root_crl) else [])
    res = sh(["openssl", "verify", "-crl_check", "-CAfile", ROOT, "-untrusted", INTER, *crls, path], ok=False)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def serial_of(pem):
    return describe_cert(pem)["serial"].replace(":", "").upper().lstrip("0")


def write(name, text):
    path = f"{W}/{name}"
    open(path, "w").write(text)
    return path


def refused(fn, *a, **k):
    try:
        fn(*a, **k)
    except ValidationError as e:
        return str(e)
    return ""


_configure_ca_json(f"{data}/config/ca.json", V)
sh(["chown", "-R", f"{STEP_UID}:{STEP_UID}", data])
save(V)
sh(["docker", "network", "create", *testrun.labels(), NET])
sh(["docker", "run", "-d", "--name", "step-ca", *testrun.labels(), "--network", NET, "--network-alias", f"ca.{DOMAIN}",
    "-v", f"{data}:/home/step", "--user", f"{STEP_UID}:{STEP_UID}", "--health-cmd",
    "step ca health --ca-url https://127.0.0.1:9000 --root /home/step/certs/root_ca.crt", "--health-interval", "2s",
    IMAGE, "/usr/local/bin/step-ca", "/home/step/config/ca.json", "--password-file", "/home/step/secrets/password"])
check("fabric's Step-CA image runs the CA (healthy)", healthy())
sh(["docker", "run", "-d", "--name", MACHINE, *testrun.labels(), "--network", NET, "--network-alias", f"nas.{DOMAIN}",
    "--user", "0:0", "-v", f"{ROOT}:/root_ca.crt:ro", "--entrypoint", "sleep", UPSTREAM, "1800"])


def acme_cert():
    sh(["docker", "exec", MACHINE, "step", "ca", "certificate", f"nas.{DOMAIN}", "/tmp/nas.crt", "/tmp/nas.key",
        "--provisioner", "acme", "--ca-url", f"https://ca.{DOMAIN}:9000", "--root", "/root_ca.crt", "--standalone",
        "--http-listen", ":80", "--force"])
    return sh(["docker", "exec", MACHINE, "cat", "/tmp/nas.crt"]).stdout


# the service certificates, as setup's certs step issues them; nothing runs systemd here: what a service would do is
# recorded, nginx (below) is sent its reload
picked = []


def pick_up(unit):
    picked.append(unit)
    if unit == "nginx":
        sh(["docker", "kill", "-s", "HUP", WEB], ok=False)
        time.sleep(2)
    return "reloaded"


rc.pick_up_cert = rsc_mod.pick_up_cert = renew_mod.pick_up_cert = pick_up
ctx = SetupContext(deploy_base=W, vars=json.loads(json.dumps(V)))
with contextlib.redirect_stdout(io.StringIO()):
    mint_service_certs.run(ctx)
VAULT = f"{W}/nginx/certs/vault.{DOMAIN}"
open(f"{W}/web.conf", "w").write("server { listen 8443 ssl; ssl_certificate /certs/fullchain.pem; "
                                 "ssl_certificate_key /certs/privkey.pem; location / { return 200 'ok'; } }\n")
sh(["docker", "run", "-d", "--name", WEB, *testrun.labels(), "-p", f"127.0.0.1:{WEB_PORT}:8443", "-v",
    f"{VAULT}:/certs:ro", "-v", f"{W}/web.conf:/etc/nginx/conf.d/default.conf:ro", NGINX])
time.sleep(2)


def served():
    out = sh(["openssl", "s_client", "-connect", f"127.0.0.1:{WEB_PORT}", "-servername", f"vault.{DOMAIN}"],
             ok=False, input="").stdout
    pem = out[out.find("-----BEGIN CERTIFICATE-----"):out.find("-----END CERTIFICATE-----") + 25]
    return serial_of(pem) if "BEGIN" in pem else ""


# ---------------------------------------------------------------- every certificate listed (1.5.1.9.1)
print("--- every certificate in Issued")
nas_pem = acme_cert()
nas = serial_of(nas_pem)
signed = list_stepca_certs(V, container="step-ca")
by = {r["serial"]: r for r in signed}
check("Step-CA's database, read through a copy: the ACME certificate with its provisioner",
      by.get(nas, {}).get("provisioner_type") == "ACME" and f"nas.{DOMAIN}" in by[nas]["sans"], signed[:3])
vault_serial = serial_of(open(f"{VAULT}/fullchain.pem").read())
check("...and the service certificates setup issued, over its JWK provisioner",
      by.get(vault_serial, {}).get("provisioner") == "admin", sorted(by))
laptop = issue_key_pair(V, "test", "laptop-9", [], "EC-P256", 30, source="cli")
lines = open(ISSUED_CERTS_FILE).read().splitlines()
entry = json.loads(lines[-1])
entry["device"] = "laptop-9"                         # linked to its device, as pki:link-device does
open(ISSUED_CERTS_FILE, "w").write("\n".join(lines[:-1] + [json.dumps(entry)]) + "\n")
listed = list_certs(V, ctx, devices={"laptop-9": {"name": "laptop-9", "roles": ["laptops"]}})
rows = {r["serial"]: r for r in listed["certs"]}
check("Issued: the LAN machine's ACME certificate, marked Over ACME and revocable",
      rows.get(nas, {}).get("source") == "acme" and rows[nas]["revocable"], rows.get(nas))
check("Issued: fabric's own, from disk, each with the services that use it, its names shown as the others' are "
      "(no openssl \"DNS:\")",
      rows.get(vault_serial, {}).get("source") == "fabric" and rows[vault_serial]["services"] == ["nginx", "openbao"]
      and f"vault.{DOMAIN}" in rows[vault_serial]["sans"]
      and not any(n.startswith("DNS:") for r in rows.values() for n in r["sans"]), rows.get(vault_serial))
laptop_serial = serial_of(laptop["cert"])
check("Issued: an 802.1X machine's certificate (linked to a device) with its device, its roles and how it was issued",
      rows.get(laptop_serial, {}).get("source") == "8021x" and rows[laptop_serial]["device"] == "laptop-9"
      and rows[laptop_serial]["device_roles"] == ["laptops"] and "PKCS#12" in rows[laptop_serial]["how"],
      rows.get(laptop_serial))
check("each certificate once (the service certificates are not listed again from the database)",
      len(listed["certs"]) == len(rows) and listed["stepca_error"] == "", listed["stepca_error"])
overview = READS[("pki", "certs")]()
# covers: agent:get.pki.certs +
check("the agent's read (GET /v1/pki/certs) answers the same list, the directory's devices unread said, not failing",
      {r["serial"] for r in overview["certs"]} == set(rows) and overview["directory_error"], overview["directory_error"])

# ---------------------------------------------------------------- refusals of a revocation (1.5.1.9.6)
print("--- refused, saying why, nothing changed")
other = f"{W}/other"
sh(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
    f"{other}.key", "-out", f"{other}.crt", "-subj", f"/CN=nas.{DOMAIN}", "-days", "30"])
inter_serial = serial_of(open(INTER).read())
for what, body, why in (
        ("a file that is not a certificate", {"pem": "hello"}, "not a certificate"),
        ("a certificate another CA signed", {"pem": open(f"{other}.crt").read()}, "did not sign"),
        ("the CA's own intermediate", {"serial": inter_serial}, "own CA certificate"),
        ("a serial this CA never signed", {"serial": "0A1B2C3D4E5F"}, "signed no certificate"),
        ("a serial that is not hexadecimal", {"serial": "not-a-serial"}, "is not a serial")):
    # covers: agent:post.pki.lookup -
    check(f"negative: {what}", why in refused(post_pki, "lookup", "test", body), refused(post_pki, "lookup", "test",
                                                                                         body))
found = post_pki("lookup", "test", {"pem": nas_pem})
# covers: agent:post.pki.lookup +
check("the ACME certificate given as a file is found as itself (POST /v1/pki/lookup)",
      found["serial"] == nas and found["source"] == "acme", found)
why = refused(post_pki, "revoke", "test", {"target": nas, "reason": "keyCompromise", "confirm": "printer"})
check("negative: the name not typed again: refused, nothing recorded",
      f"type 'nas.{DOMAIN}' to confirm" in why and revoked() == [], why)
why = refused(post_pki, "revoke", "test", {"target": inter_serial, "reason": "keyCompromise", "confirm": ""})
check("negative: the CA's own intermediate cannot be revoked", "own CA certificate" in why and revoked() == [], why)

# ---------------------------------------------------------------- a LAN machine's ACME certificate revoked
print("--- a LAN machine's ACME certificate revoked from the console")
nas_file = write("nas.crt", nas_pem)
check("before: the ACME certificate verifies against the published CRLs", verifies_with_crl(nas_file)[0],
      verifies_with_crl(nas_file))
done = post_pki("revoke", "test", {"target": nas, "reason": "keyCompromise", "confirm": f"NAS.{DOMAIN}"})
ok_now, why = verifies_with_crl(nas_file)
check("revoked (the typed name's case does not matter): recorded, in the CRL, refused by openssl's CRL check",
      done["serial"] == nas and done["replaced"] == {} and not ok_now and "revoked" in why
      and [r["serial"] for r in revoked()] == [nas], (done, why))
check("negative: already revoked", "already revoked" in refused(post_pki, "revoke", "test", {
    "target": nas, "reason": "keyCompromise", "confirm": f"nas.{DOMAIN}"}))
check("Issued marks it revoked, without Revoke", (lambda r: r["status"] == "revoked" and not r["revocable"])(
    {c["serial"]: c for c in list_certs(V, ctx)["certs"]}[nas]))

# ---------------------------------------------------------------- one of fabric's own: replaced first
print("--- fabric's own certificate: a new one in use first, then the old one revoked")
before = served()
check("before: nginx answers with the vault certificate", before == vault_serial, (before, vault_serial))
picked.clear()
done = post_pki("revoke", "test", {"target": vault_serial, "reason": "superseded", "confirm": f"vault.{DOMAIN}"})
after = served()
new_file = write("vault-new.crt", open(f"{VAULT}/fullchain.pem").read().split("-----END CERTIFICATE-----")[0]
                 + "-----END CERTIFICATE-----\n")
check("revoked after its successor: the services that use it took the new one (nginx reloaded, OpenBao)",
      sorted(done["replaced"]) == ["nginx", "openbao"] and {"nginx", "openbao"} <= set(picked), (done, picked))
check("...nginx keeps answering, now with the new certificate, which verifies against the CRL; the old one is in it",
      after and after != vault_serial and after == serial_of(open(new_file).read()) and verifies_with_crl(new_file)[0]
      and vault_serial in [r["serial"] for r in revoked()], (before, after, verifies_with_crl(new_file)))

# ---------------------------------------------------------------- Step-CA down: nothing revoked
print("--- Step-CA down")
ca_cert = f"{W}/nginx/certs/ca.{DOMAIN}/fullchain.pem"
ca_serial, ca_text, count = serial_of(open(ca_cert).read()), open(ca_cert).read(), len(revoked())
sh(["docker", "stop", "step-ca"])
check("its database is still listed, from a copy, with Step-CA stopped",
      any(r["serial"] == nas for r in list_stepca_certs(V, container="step-ca")))
why = refused(post_pki, "revoke", "test", {"target": ca_serial, "reason": "superseded", "confirm": f"ca.{DOMAIN}"})
check("negative: a service certificate whose successor cannot be issued: refused, saying so; nothing revoked, the "
      "certificate unchanged", "could not be issued, so nothing was revoked" in why and len(revoked()) == count
      and open(ca_cert).read() == ca_text, why)
sh(["docker", "start", "step-ca"])
check("Step-CA back (healthy)", healthy())

# ---------------------------------------------------------------- Lifetimes (1.5.1.10)
print("--- Lifetimes")
life = read_lifetimes(V, ctx)
left = life["intermediate_left_days"]
# covers: agent:get.pki.lifetimes +
check("the values as set, the intermediate's days left, each service certificate's next renewal (GET /v1/pki/lifetimes)",
      READS[("pki", "lifetimes")]()["values"] == life["values"] == {
          "service_days": 47, "renew_after_days": 30, "acme_days": 47, "issue_default_days": 365,
          "issue_max_days": 1825} and left and left > 365 and life["renewals"], life)
later = read_lifetimes({**V, "cert_renew_after_days": 40}, ctx)
first = {r["cn"]: r["renews"] for r in life["renewals"]}
moved = {r["cn"]: r["renews"] for r in later["renewals"]}
check("a later renew at moves each certificate's next renewal ten days on",
      all((time.strptime(moved[cn], "%Y-%m-%d") > time.strptime(first[cn], "%Y-%m-%d")) for cn in first), (first, moved))
check("certbot's matching setting is shown for the ACME lifetime", life["acme_client"]["certbot"] ==
      "renew_before_expiry = 16 days", life["acme_client"])


def restart(_run):
    sh(["docker", "restart", "step-ca"])
    if not healthy():
        raise ValidationError("Step-CA did not come back")
    return "restarted"


sl._restart_stepca = restart                       # the unit is not here: the container itself
held_before = settings()
for what, fields, why in (
        ("a lifetime longer than the intermediate has left", {"acme_days": str(left + 1)}, "longer than the "
                                                                                             "intermediate"),
        ("fabric's own under 2 days", {"service_days": "1", "renew_after_days": "1"}, "at least 2 days"),
        ("renew at with no run left before the end", {"renew_after_days": "47"}, "at least 1 day before the end"),
        ("a hand-issued default over its maximum", {"issue_default_days": "2000"}, "over the hand-issued maximum"),
        ("a value that is not whole days", {"service_days": "4x"}, "whole number of days")):
    got = refused(post_pki, "lifetimes", "test", {"fields": fields})
    held = refused(post_pending._check_lifetimes, ["pki", "lifetimes"], {"fields": fields})
    # covers: agent:post.pki.lifetimes setting:pki_manual_default_days -
    check(f"negative: {what}: refused at the hold and at the Apply, the settings unchanged",
          why in got and why in held and settings() == held_before, (got, held))
check("a server certificate over 398 days, or renewal under 7 days before the end: notes, not refusals",
      len(sl.lifetime_changes(V, {"service_days": "400", "renew_after_days": "396"})[1]) == 2)

done = post_pki("lifetimes", "test", {"fields": {"acme_days": "10", "issue_default_days": "200"}})
ca_json = json.load(open(f"{data}/config/ca.json"))
acme_claims = next(p for p in ca_json["authority"]["provisioners"] if p["type"] == "ACME")["claims"]
# covers: agent:post.pki.lifetimes setting:pki_manual_default_days +
check("a shorter ACME lifetime set: saved, Step-CA's ca.json converged and Step-CA restarted (POST /v1/pki/lifetimes)",
      done["stepca"] == "restarted" and acme_claims["maxTLSCertDuration"] == "240h"
      and yaml.safe_load(settings())["cert_acme_lifetime_hours"] == "240h", (done, acme_claims))
fresh = describe_cert(acme_cert())
span = time.mktime(time.strptime(fresh["not_after"], "%b %d %H:%M:%S %Y %Z")) - time.mktime(
    time.strptime(fresh["not_before"], "%b %d %H:%M:%S %Y %Z"))
check("...the next ACME certificate lives 10 days", abs(span - 10 * 86400) < 600, fresh)
check("...and the hand-issued forms fill in the new default", ca_summary(yaml.safe_load(settings()))["default_days"]
      == 200)
old_vault = serial_of(open(f"{VAULT}/fullchain.pem").read())
done = post_pki("lifetimes", "test", {"fields": {"service_days": "20", "renew_after_days": "10"}})
now_vault = describe_cert(open(f"{VAULT}/fullchain.pem").read())
span = time.mktime(time.strptime(now_vault["not_after"], "%b %d %H:%M:%S %Y %Z")) - time.mktime(
    time.strptime(now_vault["not_before"], "%b %d %H:%M:%S %Y %Z"))
check("a shorter lifetime for fabric's own: their 47-day certificates are renewed at the Apply, for 20 days",
      done["renewal"] == 0 and serial_of(open(f"{VAULT}/fullchain.pem").read()) != old_vault
      and abs(span - 20 * 86400) < 600, (done, now_vault))

print("--- fabricctl certs lifetimes")
for argv, code, text in ((["lifetimes"], 0, "fabric's own certificates: 20 days, renewed at 10 days old"),
                         (["lifetimes", "--acme-days"], 2, "usage"), (["lifetimes", "--bogus", "3"], 2, "usage"),
                         (["lifetimes", "--service-days", "x"], 1, "whole number of days"),
                         (["lifetimes", "--issue-max-days", "100"], 1, "over the hand-issued maximum")):
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        got = rcc.run_certs_command(SetupContext(deploy_base=W), argv)
    # `certs lifetimes`: USAGE joins REASONS, so its subcommands are not listed apart
    # covers: cli:certs +-
    check(f"fabricctl certs {' '.join(argv)}: exit {code}" + (" (refused)" if code else ""),
          got == code and text in (err.getvalue() + out.getvalue()), (got, err.getvalue()[-300:], out.getvalue()[-300:]))
with contextlib.redirect_stdout(io.StringIO()) as out:
    got = rcc.run_certs_command(SetupContext(deploy_base=W), ["lifetimes", "--issue-default-days", "100"])
check("fabricctl certs lifetimes --issue-default-days 100: set", got == 0 and "pki_manual_default_days: 200 -> 100"
      in out.getvalue(), out.getvalue())

cleanup()
sh(["docker", "image", "rm", IMAGE], ok=False)
print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
