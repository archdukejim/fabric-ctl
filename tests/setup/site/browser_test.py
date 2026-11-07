#!/usr/bin/env python3
"""Web-guided setup in a real browser (manual 1.3.6.8; global Rule 9: a UI change is checked in the running app): headless
Chromium in the test browser image (decision 2.1.8.15) goes through a real site from the certificate's fingerprint to
Finish, accepting every default, at a desktop's and a phone's width: Guided's real questions and checks, the live log over
server-sent events, the move to a certificate from a real CA, every drawing, the finish's check saying which of two things
failed, and no script or policy error on any page. Only the unit's work and the plan's host changes are stood in for: the
whole of it with a real install is tests/sandbox/web_guided.sh. Needs Docker. Set SITE_PICTURES to a folder to keep each
page's picture.

    sudo python3 tests/setup/site/browser_test.py
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from support import REPO, check, finish, free_ports, listener_lib  # noqa: E402

sys.path.insert(0, os.path.join(REPO, "tests", "common"))
import test_run as testrun  # noqa: E402

import fabriclib.setup.choose_plan as cp  # noqa: E402
import fabriclib.setup.collect_vars as cv  # noqa: E402
import fabriclib.setup.detach.follow_run as fr  # noqa: E402
import fabriclib.setup.site.finish_data as fd  # noqa: E402
import fabriclib.setup.site.guided_site as gs  # noqa: E402
from fabriclib.setup.apply_plan_defaults import apply_plan_defaults  # noqa: E402
from fabriclib.setup.ask_first_admin import ask_first_admin  # noqa: E402
from fabriclib.setup.choose_plan import choose_plan  # noqa: E402
from fabriclib.setup.collect_vars import collect_vars  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.constants import LOG  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402

IMAGE, NAME = "fabric/webui-browser:" + testrun.name("site"), testrun.name("csite")
CONSOLE, SECRET = "fabric-ctl.lan.example", "Correct-Horse-Battery-9"
DEBIAN = subprocess.run([sys.executable, os.path.join(REPO, "tests", "image_ref.py"), "debian"], capture_output=True, text=True,
                        check=True).stdout.strip()
DOCKERFILE = f"""FROM {DEBIAN}
RUN apt-get update && apt-get install -y --no-install-recommends chromium python3 openssl fonts-dejavu-core \\
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m probe
USER probe
"""
NET = {"hostname": "fabric-test", "host_ip": "127.0.0.1", "lan_gateway": "127.0.0.2", "lan_cidr": "127.0.0.0/8", "interface": "lo"}
gs.detect_network = lambda: NET
cv.detect_network = lambda: NET
cv.network_problem = lambda data: ""
gs.open_site_port = lambda port, cidr: False
gs.check_console = lambda ctx: ""
cp.show_memory_plan = lambda rendered, label: print("  memory plan: stood in for")
fr.ENDED_GAP = 0.1
LIB, USER = listener_lib()


class Term:
    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass


def openssl(*args):
    subprocess.run(["openssl", *args], capture_output=True, check=True)


def make_ca(folder):
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{folder}/root.key",
            "-out", f"{folder}/root-ca.crt", "-days", "2", "-subj", "/CN=fabric test root")
    openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{folder}/leaf.key",
            "-out", f"{folder}/leaf.csr", "-subj", "/CN=127.0.0.1")
    with open(f"{folder}/ext", "w") as f:
        f.write(f"subjectAltName=IP:127.0.0.1,DNS:{CONSOLE}\n")
    openssl("x509", "-req", "-in", f"{folder}/leaf.csr", "-CA", f"{folder}/root-ca.crt", "-CAkey", f"{folder}/root.key",
            "-CAcreateserial", "-days", "1", "-extfile", f"{folder}/ext", "-out", f"{folder}/leaf.crt")
    with open(f"{folder}/leaf.crt") as f:
        chain = f.read()
    with open(f"{folder}/leaf.key") as f:
        return chain, f.read()


class Console(BaseHTTPRequestHandler):
    """Stands for the console's nginx in this test: answers, on fabric's certificate."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def console_on(folder):
    server = HTTPServer(("127.0.0.1", 0), Console)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{folder}/leaf.crt", f"{folder}/leaf.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def plan_host():
    return None, {"packages": ["apt: docker.io, docker-compose-v2"], "firewall": ["ufw: deny incoming and allow outgoing by default"]}


def one_run(width, base, pictures):
    """The whole of it at one width. Returns what the probe printed (rows) and the terminal's text."""
    chain, key = make_ca(base)
    fd.mint_site_cert = lambda c, addresses, name: (chain, key)
    first, last = free_ports()
    term = Term()
    ctx = SetupContext(deploy_base=base)
    site = gs.GuidedSite(ctx, term=term, first=first, last=last, record=os.path.join(base, "site-port"), lib_dir=LIB, user=USER,
                         grace=1.0, after=30)
    site.open()
    code = next(line.split()[-1] for line in term.text.splitlines() if "code:" in line)
    port_console = console_on(base)
    folder = tempfile.mkdtemp(prefix="site-probe-", dir="/tmp")
    os.chmod(folder, 0o777)
    scenario = {"url": f"https://127.0.0.1:{site.port}/", "code": code, "fingerprint": site.fingerprint, "out": "/out", "width": width,
                "secret": SECRET, "pictures": bool(pictures), "finish_check": True, "restart_wait": 3, "seconds": 120,
                "answers": {"DNS domain": "lan.example", "First Directory": "pat.admin", "Their first": "Pat", "Their last": "Example"},
                "watch_log_for": "step 3 of the install",
                "check_with": {"resolved": {f"{CONSOLE}:443": f"127.0.0.1:{port_console}", CONSOLE: "127.0.0.1"}}}
    with open(os.path.join(folder, "scenario.json"), "w") as f:
        json.dump(scenario, f)
    rows = []

    def drive():
        run = subprocess.run(["docker", "run", "--rm", "--name", NAME, *testrun.labels(), "--network", "host", "--memory", "1g", "--shm-size", "256m",
                              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", f"{HERE}:/probe:ro", "-v", f"{folder}:/out",
                              IMAGE, "python3", "/probe/site_probe.py", "/out/scenario.json"],
                             capture_output=True, text=True, timeout=300)
        rows.extend(json.loads(line) for line in run.stdout.splitlines() if line.startswith("{"))
        if run.returncode:
            rows.append({"probe_failed": run.returncode, "stderr": run.stderr[-1500:]})
            site.cancelled = True              # setup would wait for its answers until the idle limit
            site.answers.put({"t": "cancel"})
            site.done.set()
    thread = threading.Thread(target=drive, daemon=True)
    thread.start()
    result = decided = None
    try:
        ctx.vars = {}
        collect_vars(ctx)
        apply_plan_defaults(ctx)
        ctx.host_choices = {}
        ask_first_admin(ctx)
        decided = choose_plan(ctx, plan_host)
        site.proceeding()
        os.makedirs(ctx.path("nginx", "www", "certs"), exist_ok=True)
        shutil.copy(os.path.join(base, "root-ca.crt"), ctx.path("nginx", "www", "certs", "root-ca.crt"))
        with open(ctx.vars_file, "w") as f:
            f.write(f"host_ip: 127.0.0.1\ndomain: lan.example\nhostname_mgr: {CONSOLE}\n")
        path = os.path.join(ctx.config_dir, LOG)
        open(path, "w").close()
        running = [True]

        def work():
            with open(path, "a") as f:
                for n in range(16):
                    f.write(f"  ✓ step {n} of the install\n")
                    f.flush()
                    time.sleep(0.4)
            write_run(ctx.config_dir, {"id": "b", "state": "done", "result": 0, "done": []})
            running[0] = False
        threading.Thread(target=work, daemon=True).start()
        saved = gs.follow_run
        gs.follow_run = lambda config_dir, out=None: saved(config_dir, running=lambda: running[0], out=out, sleep=time.sleep, interval=0.1)
        result = site.follow(ctx.config_dir)
        gs.follow_run = saved
    except SystemExit:
        decided = None
    finally:
        port = site.port
        site.close()
    thread.join(60)
    testrun.remove("container", NAME)
    if pictures:
        os.makedirs(pictures, exist_ok=True)
        for name in os.listdir(folder):
            if name.endswith(".png"):
                shutil.copy(os.path.join(folder, name), pictures)
    shutil.rmtree(folder, ignore_errors=True)
    shutil.rmtree(ctx.target_dir, ignore_errors=True)
    return rows, result, decided, term.text, port


build = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"], input=DOCKERFILE, text=True, capture_output=True)
check("the test browser image builds (pinned Debian, Debian's chromium)", build.returncode == 0, build.stderr[-800:])
if build.returncode:
    sys.exit(1)
try:
    for width in (1366, 375):
        with tempfile.TemporaryDirectory() as base:
            rows, result, decided, term, port = one_run(width, base, os.environ.get("SITE_PICTURES"))
        pages = {r["page"]: r for r in rows if "page" in r}
        at = f"at {width} px:"
        check(f"{at} Chromium went from the code to Finish, every default accepted", rows and rows[-1].get("done") is True and result == 0,
              [{k: str(v)[:700] for k, v in r.items()} for r in rows[-4:]])
        check(f"{at} the code page shows the fingerprint and the warning", "fingerprint" in pages.get("code", {}).get("text", "") and "intercept" in pages.get("code", {}).get("text", ""), pages.get("code"))
        check(f"{at} a question marked permanent shows it", any("Permanent" in r.get("text", "") for r in rows if r.get("page", "").startswith("q")))
        check(f"{at} the password was asked twice, in fields that hide it", sum("Password for" in r.get("label", "") or "same again" in r.get("label", "") for r in rows) == 2, [r.get("label") for r in rows])
        check(f"{at} the plan shows the host changes and one confirmation", "docker.io" in pages.get("plan", {}).get("text", "") and "Proceed" in pages.get("plan", {}).get("text", ""), pages.get("plan"))
        check(f"{at} Proceed allowed the plan's groups", decided == {"packages": True, "firewall": True}, decided)
        check(f"{at} the log comes live, without a reload (server-sent events)", any(r.get("event") == "live log" for r in rows), [r.get("event") for r in rows])
        check(f"{at} the page warned of the new certificate, with its fingerprint", "restarting" in pages and any(r.get("event") == "new certificate" for r in rows), list(pages))
        check(f"{at} the finish shows trust, DNS, the check and onward", all(w in pages.get("finish", {}).get("text", "") for w in ("Trust fabric", "DNS", "Check", "login kit")), pages.get("finish"))
        check(f"{at} every drawing loaded", not pages.get("finish", {}).get("broken") and pages.get("finish", {}).get("css"), pages.get("finish"))
        checks = {r["stage"]: r["text"] for r in rows if r.get("event") == "check"}
        check(f"{at} the check, with the name not resolving: says it is the name", "did not resolve" in checks.get("first", ""), checks)
        check(f"{at} the check, with the name resolving and the certificate accepted: passes", checks.get("resolved", "").startswith("OK:"), checks)
        check(f"{at} Finish says the site stopped", "stopped" in pages.get("closed", {}).get("text", "") or "has closed" in pages.get("closed", {}).get("text", ""), pages.get("closed"))
        wide = {name: r["scroll"] for name, r in pages.items() if r.get("wide")}
        check(f"{at} nothing wider than the screen on any page", not wide, wide)
        errors = [e for r in rows for e in r.get("errors", [])]
        check(f"{at} no script error and no content-policy refusal on any page", not errors, errors)
finally:
    testrun.remove("container", NAME)
    subprocess.run(["docker", "rmi", IMAGE], capture_output=True)

sys.exit(finish("browser_test"))
