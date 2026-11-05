#!/usr/bin/env python3
"""The Linux join's first steps as the certificates page gives them (decision 2.1.1.85, manual 4.6.6.2), run for real: the
page rendered, its block taken from it unchanged, in real Ubuntu and Debian containers, with curl and with wget alone,
against a real TLS server. Proves: the script arrives and runs; a wrong fingerprint and a root that is not fabric's are each
refused, saying why, with nothing run; and that a server the machine's own system store would accept (the trap of 2.3.1.49)
still cannot vouch for it.

    sudo python3 tests/samba/join_steps.py
"""
import html
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__)), os.path.join(REPO, "tests", "common")]
import test_run as testrun  # noqa: E402
from fabriclib.common.jinja_env import jinja_env  # noqa: E402
from start_dc import IMAGE as SAMBA_IMAGE  # noqa: E402

FAILED = 0
CA_NAME, OWN = "ca.lab.test", "host-1.lab.test"
NET = testrun.name("js-net")
SERVER = testrun.name("js-web")
IMAGES = {"24.04": "ubuntu:24.04", "debian-13": "debian:13"}
SERVE = r"""
import http.server, ssl, threading
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory="/srv", **k)
plain = http.server.ThreadingHTTPServer(("", 80), H)
threading.Thread(target=plain.serve_forever, daemon=True).start()
tls = http.server.ThreadingHTTPServer(("", 443), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain("/tls/leaf.crt", "/tls/leaf.key")
tls.socket = c.wrap_socket(tls.socket, server_side=True)
tls.serve_forever()
"""


def check(name, cond, detail=""):
    global FAILED
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"  -> {detail}" if not cond else ""))
    FAILED += 0 if cond else 1


def sh(cmd, ok=True, **kw):
    res = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if ok and res.returncode:
        raise SystemExit(f"{cmd}: {res.stderr[-400:]}")
    return res


def on(box, script):
    res = sh(["docker", "exec", box, "bash", "-c", script], ok=False)
    return res.returncode, res.stdout + res.stderr


def root(folder, name):
    sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{folder}/{name}.key", "-subj",
        f"/CN={name} root", "-days", "2", "-addext", "basicConstraints=critical,CA:TRUE", "-out", f"{folder}/{name}.crt"])
    fp = sh(["openssl", "x509", "-in", f"{folder}/{name}.crt", "-noout", "-fingerprint", "-sha256"]).stdout
    return fp.split("=")[1].strip()


def cleanup():
    sh(["docker", "rm", "-f", SERVER, *BOXES], ok=False)
    sh(["docker", "network", "rm", NET], ok=False)


BOXES = []
page = jinja_env(os.path.join(REPO, "templates")).get_template(
    "nginx/www/certs/index.html.j2").render(hostname_stepca=CA_NAME, hostname="host-1", domain="lab.test", domain_file="lan",
                                            host_ip="10.0.0.1", ad_domain="ad.lab.test")
found = re.search(r'<pre id="join-steps"><code>(.*?)</code></pre>', page, re.S)
check("the page has the join's steps", bool(found))
block = html.unescape(found.group(1))
check("...and its script comes by HTTPS alone", f"http://{CA_NAME}/certs/root-ca.crt" in block
      and f"https://{OWN}/certs/join-linux.sh" in block and not re.search(r"http://\S*join-linux", block), block)


def steps(fp):
    return block.replace("<root CA SHA-256 from above>", fp).replace("<directory admin>", "adam")


tmp = tempfile.mkdtemp(prefix="join-steps-")
os.chmod(tmp, 0o755)
try:
    www, tls = os.path.join(tmp, "www"), os.path.join(tmp, "tls")
    os.makedirs(os.path.join(www, "certs"))
    os.makedirs(tls)
    FABRIC_FP, OTHER_FP = root(tls, "fabric"), root(tls, "other")
    sh(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{tls}/leaf.key", "-subj", f"/CN={OWN}", "-out", f"{tls}/leaf.csr"])
    with open(f"{tls}/ext", "w") as f:
        f.write(f"subjectAltName=DNS:{OWN},DNS:{CA_NAME}\n")
    sh(["openssl", "x509", "-req", "-in", f"{tls}/leaf.csr", "-CA", f"{tls}/fabric.crt", "-CAkey", f"{tls}/fabric.key", "-CAcreateserial",
        "-days", "2", "-extfile", f"{tls}/ext", "-out", f"{tls}/leaf.crt"])
    with open(os.path.join(www, "certs", "join-linux.sh"), "w") as f:
        f.write('echo "ran with: $*" > /tmp/ran\n')
    served_root = os.path.join(www, "certs", "root-ca.crt")
    with open(f"{tls}/fabric.crt") as f, open(served_root, "w") as g:
        g.write(f.read())
    for folder, _d, files in os.walk(tmp):
        for name in files:
            os.chmod(os.path.join(folder, name), 0o644)
        os.chmod(folder, 0o755)
    sh(["docker", "network", "create", *testrun.labels(), NET])
    sh(["docker", "run", "-d", "--name", SERVER, *testrun.labels(), "--network", NET, "--network-alias", CA_NAME, "--network-alias", OWN,
        "-v", f"{www}:/srv:ro", "-v", f"{tls}:/tls:ro", "--entrypoint", "python3", SAMBA_IMAGE, "-c", SERVE])

    for release, image in IMAGES.items():
        for client in ("curl", "wget"):
            box = testrun.name(f"js-{release}-{client}".replace(".", ""))
            BOXES.append(box)
            sh(["docker", "run", "-d", "--name", box, *testrun.labels(), "--network", NET, "-v", f"{tls}:/tls:ro", image, "sleep", "infinity"])
            code, out = on(box, "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends "
                                f"ca-certificates openssl {client} >/dev/null; printf '#!/bin/sh\\nexec \"$@\"\\n' > /usr/local/bin/sudo; "
                                "chmod +x /usr/local/bin/sudo; mkdir -p /w; sleep 1")
            who = f"{release}, {client}"
            check(f"{who}: the client is ready, with no other way to fetch", code == 0, out[-300:])

            def run(fp):
                """The block as pasted, in an empty folder; what it said, and whether it ran the script."""
                on(box, "rm -f /tmp/ran /w/*")
                with open(os.path.join(tmp, "steps.sh"), "w") as f:
                    f.write(steps(fp))
                sh(["docker", "cp", os.path.join(tmp, "steps.sh"), f"{box}:/w/.steps"])
                code, out = on(box, "cd /w; bash .steps; echo rc=$?; test -e /tmp/ran && cat /tmp/ran && echo RAN; "
                                    "test -e /w/join-linux.sh && echo KEPT-SCRIPT")
                return out

            out = run(FABRIC_FP)
            check(f"{who}: the right fingerprint: the root, then the script by HTTPS, and it runs with the fingerprint",
                  "rc=0" in out and "RAN" in out and f"ran with: {FABRIC_FP} --user adam" in out, out)
            out = run(FABRIC_FP.lower())
            check(f"{who}: the fingerprint however it was typed (lower case)", "rc=0" in out and "RAN" in out, out)
            out = run(FABRIC_FP.replace(":", ""))
            check(f"{who}: the fingerprint however it was typed (no colons)", "rc=0" in out and "RAN" in out, out)
            out = run("00:" * 31 + "00")
            check(f"negative, {who}: a wrong fingerprint: refused, saying why, the script neither fetched nor run",
                  "rc=1" in out and "is not the fingerprint you gave" in out and "RAN" not in out and "KEPT-SCRIPT" not in out, out)
            out = run("")
            check(f"negative, {who}: no fingerprint: refused, nothing run",
                  "rc=1" in out and "is not the fingerprint you gave" in out and "RAN" not in out and "KEPT-SCRIPT" not in out, out)
            # a root that is not fabric's served over the plain HTTP, the admin holding fabric's fingerprint
            with open(f"{tls}/other.crt") as f, open(served_root, "w") as g:
                g.write(f.read())
            out = run(FABRIC_FP)
            check(f"negative, {who}: another root served, fabric's fingerprint held: refused, saying why, nothing run",
                  "rc=1" in out and "is not the fingerprint you gave" in out and "RAN" not in out and "KEPT-SCRIPT" not in out, out)
            # the fingerprint and the served root agree, on a root the HTTPS server cannot prove itself with
            out = run(OTHER_FP)
            check(f"negative, {who}: a root that is not the server's, its own fingerprint held: refused, saying why, nothing run",
                  "rc=1" in out and "did not prove itself" in out and "RAN" not in out and "KEPT-SCRIPT" not in out, out)
            # the trap (2.3.1.49): the machine's own store does trust the server; the steps must not take that as trust
            on(box, "cp /tls/fabric.crt /usr/local/share/ca-certificates/in-store.crt; update-ca-certificates >/dev/null 2>&1")
            out = run(OTHER_FP)
            check(f"negative, {who}: the same with the server's root in the system store: still refused, nothing run",
                  "rc=1" in out and "did not prove itself" in out and "RAN" not in out and "KEPT-SCRIPT" not in out, out)
            on(box, "rm -f /usr/local/share/ca-certificates/in-store.crt; update-ca-certificates --fresh >/dev/null 2>&1")
            with open(f"{tls}/fabric.crt") as f, open(served_root, "w") as g:
                g.write(f.read())
finally:
    cleanup()
    subprocess.run(["rm", "-rf", "--", tmp], check=False)
print("\nall passed (0 failures)" if not FAILED else f"\nFAILED ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
