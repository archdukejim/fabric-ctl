"""Web-guided setup after Proceed (manual 1.3.6.5, 1.3.6.6, 1.3.6.8), a real listener process with real TLS and a real
CA (openssl): the run's log live, a dropped connection stopping nothing, the same code reconnecting, a failed step on the
page, the move to the new certificate, the root offered, the check saying which of two things failed, Finish, and
nothing left. Only systemd's unit is stood in for, by a thread writing the run's log and record as the unit does; the
whole of it with a real install is tests/sandbox/web_guided.sh.
    python3 tests/setup/site/flow_test.py"""
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from support import Browser, check, finish, free_ports, listener_lib  # noqa: E402

import fabriclib.setup.site.finish_data as fd  # noqa: E402
import fabriclib.setup.site.guided_site as gs  # noqa: E402
import fabriclib.setup.detach.follow_run as fr  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.constants import LOG  # noqa: E402
from fabriclib.setup.detach.write_run import write_run  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.certificate_fingerprint import certificate_fingerprint  # noqa: E402
from fabriclib.setup.site.listener.check_verdict import check_verdict  # noqa: E402

LIB, USER = listener_lib()
NET = {"hostname": "fabric-test", "host_ip": "127.0.0.1", "lan_gateway": "127.0.0.2", "lan_cidr": "127.0.0.0/8", "interface": "lo"}
gs.detect_network = lambda: NET
gs.open_site_port = lambda port, cidr: False
gs.check_console = lambda ctx: ctx.host_problem
fr.ENDED_GAP = 0.05
CONSOLE = "fabric-ctl.lan.example"


class Term:
    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass

    def code(self):
        return [line.split()[-1] for line in self.text.splitlines() if "code:" in line][-1]


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, text=True, check=True).stdout


def make_ca(folder):
    """A real root and a leaf for the console's name and the address, as Step-CA gives."""
    # a CA with keyUsage, as fabric's own root has (init_pki): Python 3.13+ verifies strictly (VERIFY_X509_STRICT)
    # and refuses a CA without it (2.3.1.59)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{folder}/root.key",
            "-out", f"{folder}/root-ca.crt", "-days", "2", "-subj", "/CN=fabric test root", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
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


def new_site(base, grace=0.3):
    first, last = free_ports()
    term = Term()
    ctx = SetupContext(deploy_base=base)
    ctx.host_problem = ""
    site = gs.GuidedSite(ctx, term=term, first=first, last=last, record=os.path.join(base, "site-port"), lib_dir=LIB, user=USER,
                         grace=grace, after=30, attach=os.path.join(base, "attach.sock"))
    site.open()
    return site, term, Browser(site.port)


def write_vars(ctx):
    os.makedirs(ctx.config_dir, exist_ok=True)
    with open(ctx.vars_file, "w") as f:
        f.write(f"host_ip: 127.0.0.1\ndomain: lan.example\nhostname_mgr: {CONSOLE}\n")


class Run:
    """Stands in for fabric-setup.service: writes the log and the record as the unit does, and says when it runs."""

    def __init__(self, ctx, lines, state, result=0):
        self.ctx, self.lines, self.state, self.result = ctx, lines, state, result
        self.running = True
        self.go = threading.Event()
        os.makedirs(ctx.config_dir, exist_ok=True)
        self.path = os.path.join(ctx.config_dir, LOG)
        open(self.path, "w").close()

    def work(self):
        with open(self.path, "a") as f:
            for line in self.lines:
                f.write(line + "\n")
                f.flush()
                time.sleep(0.05)
            self.go.wait(20)
            f.write("the last line\n")
        write_run(self.ctx.config_dir, {"id": "r", "state": self.state, "result": self.result, "done": []})
        self.running = False

    def follow_as_unit(self, site):
        saved = gs.follow_run

        def follow(config_dir, out=None):
            return saved(config_dir, running=lambda: self.running, out=out, sleep=time.sleep, interval=0.05)
        gs.follow_run = follow
        threading.Thread(target=self.work, daemon=True).start()
        try:
            return site.follow(self.ctx.config_dir)
        finally:
            gs.follow_run = saved


def background(fn):
    box = {}

    def run():
        box["value"] = fn()
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def listening(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_for(text, get, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        page = get()
        if text in page:
            return page
        time.sleep(0.1)
    return page


def stream_lines(browser, count, after=0):
    """Read a few events of the live stream, as a browser's EventSource does."""
    raw = ssl._create_unverified_context().wrap_socket(socket.create_connection((browser.host, browser.port), timeout=8))
    raw.sendall(f"GET /events?after={after} HTTP/1.1\r\nHost: x\r\nCookie: {browser.cookie}\r\n\r\n".encode())
    text = ""
    try:
        while text.count("event: log") < count:
            chunk = raw.recv(65536)
            if not chunk:
                break
            text += chunk.decode()
    except OSError:
        pass
    raw.close()
    return text


with tempfile.TemporaryDirectory() as base:
    # ---- a good run, to the finish ----
    site, term, browser = new_site(base)
    ctx, port = site.ctx, site.port
    browser.post("/code", {"code": term.code()})
    site.proceeding()
    status, page, _ = browser.get()
    check("after Proceed the page shows the install", "Installing fabric" in page, page[:400])
    check("the page says the relaxation goes on", "Temporary certificate in use" in page)
    check("the page reloads without script", 'http-equiv="refresh"' in page and "<noscript>" in page, page[:400])
    check("the terminal says how to recover if the page is cut off", "follows the run again" in term.text and "finish's steps" in term.text, term.text[-400:])
    chain, key = make_ca(base)
    os.makedirs(ctx.path("nginx", "www", "certs"), exist_ok=True)
    shutil.copy(os.path.join(base, "root-ca.crt"), ctx.path("nginx", "www", "certs", "root-ca.crt"))
    write_vars(ctx)
    minted = []
    fd.mint_site_cert = lambda c, addresses, name: minted.append((addresses, name)) or (chain, key)
    run = Run(ctx, [f"step line {n}" for n in range(30)], "done")
    t, box = background(lambda: run.follow_as_unit(site))
    page = wait_for("step line 5", lambda: browser.get()[1])
    check("the page opens with the run's log so far", "step line 5" in page, page[:300])
    status, page, _ = browser.post("/cancel", {"csrf": site.keeper.csrf})
    check("Cancel after Proceed: refused, saying the work goes on", status == 409 and "goes on" in page, page[:300])  # covers: site:post.cancel -
    site._on_message({"t": "cancel"})
    check("and root would not take it either", not site.cancelled)
    events = stream_lines(browser, 3)  # covers: site:get.events +
    check("the live stream gives log lines, each with its number", "event: log" in events and "id: " in events and "step line" in events, events[:400])
    resumed = stream_lines(browser, 1, after=20)
    check("a reconnect asks from where it was: nothing it has is sent twice", "step line 0\n" not in resumed and "step line 19\n" not in resumed and "step line 20" in resumed, resumed[:400])
    # the connection dropped after Proceed
    dropped = Browser(port)
    dropped_status, asked, _ = dropped.post("/code", {"code": term.code()})
    check("a second browser is asked first while the first holds the session", dropped_status == 409 and "open in another browser" in asked, dropped_status)
    status, _, _ = dropped.post("/code", {"ticket": dropped.field(asked, "ticket")})
    check("connection dropped after Proceed: nothing stopped, and the code opens the site again", status == 303 and run.running and t.is_alive(), status)
    browser = dropped
    status, page, _ = browser.get()
    check("reconnected: the same run's log", "step line" in page and "Installing" in page, page[:300])
    check("the terminal shows the same progress", "step line 3" in term.text, term.text[-300:])

    run.go.set()
    # the move to the new certificate
    deadline = time.time() + 25
    page = ""
    saw_restarting = False
    while time.time() < deadline:
        try:
            page = browser.get()[1]
        except (OSError, ssl.SSLError):
            time.sleep(0.05)
            continue
        saw_restarting = saw_restarting or "moving to fabric" in page
        if "fabric is installed" in page:
            break
        time.sleep(0.03)
    check("before the move, the page gives the new certificate's fingerprint", saw_restarting, page[:300])
    check("the finish shows", "fabric is installed" in page, page[:600])
    check("the certificate's minted for the address and the console's name", minted and minted[0][1] == CONSOLE and minted[0][0][0] == "127.0.0.1", minted)
    with ssl._create_unverified_context().wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5)) as s:
        served = certificate_fingerprint(ssl.DER_cert_to_PEM_cert(s.getpeercert(True)))
    check("the site now serves fabric's own certificate", served == certificate_fingerprint(chain), served)
    good = ssl.create_default_context(cafile=os.path.join(base, "root-ca.crt"))
    with good.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname="127.0.0.1") as s:
        check("a client trusting fabric's root connects with no warning", s.version() is not None)
    fp = certificate_fingerprint(open(os.path.join(base, "root-ca.crt")).read())
    check("the finish shows the root's fingerprint", fp in page, page[:600])
    check("the terminal also prints the root's fingerprint, and the new certificate's", fp in term.text and served in term.text, term.text[-500:])
    check("the temporary certificate's notice has gone", "Temporary certificate in use" not in page)
    check("the session lived through the restart", 'action="/finish"' in page, page[:300])
    check("the pictures are fabric's drawings, on the page", "/static/trust-windows.svg" in page and "/static/dns-ubuntu.svg" in page)
    status, svg, r = browser.get("/static/trust-windows.svg")
    check("a drawing is served as an image, with no OS's artwork", status == 200 and r.getheader("Content-Type").startswith("image/svg") and "<svg" in svg, svg[:100])  # covers: site:get.static.* +
    check("nothing but the site's files is served", browser.get("/static/../../etc/passwd")[0] == 404 and browser.get("/static/guided_site.py")[0] == 404)  # covers: site:get.static.* -
    check("the DNS commands have the real address and domain filled in",
          'Add-DnsClientNrptRule -Namespace ".lan.example" -NameServers "127.0.0.1"' in page.replace("&quot;", '"')
          and "/etc/resolver/lan.example" in page and "Domains=~lan.example" in page and "<domain>" not in page.replace("&lt;domain&gt;", "<domain>"), page[:200])
    check("the trust installers are named at the certs page", "http://127.0.0.1/certs/root-ca.cer" in page)
    status, pem, r = browser.get("/root-ca.crt")
    check("the root certificate is offered for download", status == 200 and "BEGIN CERTIFICATE" in pem and "attachment" in r.getheader("Content-Disposition"))  # covers: site:get.root-ca.crt +
    check("the console's link and the login kit", f"https://{CONSOLE}/" in page and "fabric-admin" in page)
    check("the console's name is allowed to the finish's check, and nothing else",
          f"connect-src 'self' https://{CONSOLE} https://{CONSOLE}:{port};" in browser.get()[2].getheader("Content-Security-Policy"), browser.get()[2].getheader("Content-Security-Policy"))

    # the check: real TLS hellos and requests
    def result(nonce, console="1"):
        return json.loads(browser.get(f"/check-result/{nonce}?console={console}")[1])

    check("no hello naming the console: it is the name that failed", result("nonce1")["failed"] == "dns", result("nonce1"))  # covers: site:get.check-result.* +
    # a browser that resolves the name here but does not trust the root: the hello arrives, the request does not
    untrusting = ssl.create_default_context()
    try:
        with untrusting.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname=CONSOLE):
            pass
    except ssl.SSLError:
        pass
    check("the name resolves here but the certificate is not trusted: it is the trust that failed", result("nonce2")["failed"] == "trust", result("nonce2"))
    named = Browser(port, cafile=os.path.join(base, "root-ca.crt"), host="127.0.0.1")
    named.tls.check_hostname = False
    import http.client  # noqa: E402
    c = http.client.HTTPSConnection("127.0.0.1", port, context=named.tls, timeout=5)
    c.sock = named.tls.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5), server_hostname=CONSOLE)
    c.request("GET", "/check/nonce3")
    check("the check's request needs no session", c.getresponse().status == 204)  # covers: site:get.check.* +
    c.close()
    check("both hold: the check passes", result("nonce3")["ok"], result("nonce3"))
    check("the console itself not answering: said apart", result("nonce3", "0")["failed"] == "console", result("nonce3", "0"))
    ctx.host_problem = "fabric's DNS at 127.0.0.1 answers nothing"
    verdict = result("nonce3")
    check("the host's own look found a problem: named", verdict["failed"] == "console" and "answers nothing" in verdict["text"], verdict)
    ctx.host_problem = ""
    anon = Browser(port)
    check("the check's result needs a session", anon.get("/check-result/nonce3")[0] == 401)  # covers: site:get.check-result.* -
    check("an unknown check is no check", result("other")["failed"] != "", result("other"))  # covers: site:get.check.* -
    check("the verdict's words", "resolves here" in check_verdict(True, True, True, "", "x")["text"])

    status, page, _ = browser.post("/finish", {"csrf": "stale"})
    check("Finish with a stale token: refused, the site stays", status == 403 and listening(port), page[:200])  # covers: site:post.finish -
    csrf = browser.field(browser.get()[1], "csrf")
    status, page, _ = browser.post("/finish", {"csrf": csrf})
    check("Finish: told the site has stopped", status == 200 and "has closed" in page, page[:300])  # covers: site:post.finish +
    t.join(15)
    check("the run's result is the exit status", box.get("value") == 0, box)
    pid = site.process.pid if site.process else 0
    site.close()
    check("after Finish the port is closed", not listening(port))
    check("after Finish the listener has gone: nothing is listening", not pid or not os.path.exists(f"/proc/{pid}"))
    check("after Finish the key and the code are gone from setup's memory", not site.key and not site.cert and not site.keeper.code and not site.keeper.token)
    check("after Finish the port's record is gone", not os.path.exists(os.path.join(base, "site-port")))
    check("a finished run keeps the install's files (only before Proceed is the folder put back)", os.path.exists(ctx.vars_file))
    shutil.rmtree(ctx.target_dir)

    # ---- the new certificate cannot be had ----
    site, term, browser = new_site(base)
    ctx, port = site.ctx, site.port
    browser.post("/code", {"code": term.code()})
    site.proceeding()
    write_vars(ctx)

    def no_mint(c, a, n):
        raise SetupError("minting failed: the CA said no")
    fd.mint_site_cert = no_mint
    run = Run(ctx, ["a line"], "done")
    run.go.set()
    t, box = background(lambda: run.follow_as_unit(site))
    page = wait_for("fabric is installed", lambda: browser.get()[1])
    check("the CA will not give a new certificate: the finish still shows, on the temporary one, saying so",
          "stays on its temporary certificate" in page and "Temporary certificate in use" in page and "fabric is installed" in page, page[:800])
    status, _, _ = browser.post("/finish", {"csrf": browser.field(browser.get()[1], "csrf")})
    t.join(15)
    site.close()
    shutil.rmtree(ctx.target_dir)

    # ---- the site cannot restart on the new certificate ----
    site, term, browser = new_site(base)
    ctx, port = site.ctx, site.port
    browser.post("/code", {"code": term.code()})
    site.proceeding()
    chain, key = make_ca(base)
    os.makedirs(ctx.path("nginx", "www", "certs"), exist_ok=True)
    shutil.copy(os.path.join(base, "root-ca.crt"), ctx.path("nginx", "www", "certs", "root-ca.crt"))
    write_vars(ctx)
    fd.mint_site_cert = lambda c, a, n: (chain, key)

    def no_listener(*args):
        raise SetupError("the setup site could not start: it died. Run Guided here instead: sudo fabricctl setup --terminal. Nothing was changed.")
    site.listener.start = no_listener
    run = Run(ctx, ["a line"], "done")
    run.go.set()
    result = run.follow_as_unit(site)
    check("the restart fails after a good install: setup still ends well, saying where the finish's steps are",
          result == 0 and "fabric is installed" in term.text and "4.3.6.2" in term.text and "Nothing was changed" not in term.text, (result, term.text[-500:]))
    site.close()
    shutil.rmtree(ctx.target_dir)

    # ---- a failed step ----
    site, term, browser = new_site(base)
    ctx, port = site.ctx, site.port
    browser.post("/code", {"code": term.code()})
    site.proceeding()
    run = Run(ctx, ["a good step", "✗ the docker step failed: no network"], "failed", result=1)
    run.go.set()
    t, box = background(lambda: run.follow_as_unit(site))
    page = wait_for("Setup stopped", lambda: browser.get()[1])
    check("a failed step: the page says so, with the step's message", "Setup stopped" in page and "the docker step failed" in page, page[:800])
    check("a failed step: the page says how to resume", "resumes from that step" in page, page[:800])
    check("a failed step: no root offered", browser.get("/root-ca.crt")[0] == 404)  # covers: site:get.root-ca.crt -
    status, _, _ = browser.post("/finish", {"csrf": browser.field(browser.get()[1], "csrf")})
    t.join(15)
    check("a failed step's status is setup's", box.get("value") == 1, box)
    site.close()
    check("then the port is closed", not listening(port))
    shutil.rmtree(ctx.target_dir)

    # ---- the one-hour limit after setup's end ----
    site, term, browser = new_site(base)
    site.after = 0.3
    ctx, port = site.ctx, site.port
    site.proceeding()
    os.makedirs(ctx.path("nginx", "www", "certs"), exist_ok=True)
    write_vars(ctx)
    fd.mint_site_cert = no_mint
    run = Run(ctx, ["a line"], "done")
    run.go.set()
    code = run.follow_as_unit(site)
    site.close()
    check("the time limit after the end stops the site by itself", code == 0 and not listening(port), code)
    shutil.rmtree(ctx.target_dir)

    # ---- Ctrl-C, a real signal to a real process ----
    driver = os.path.join(HERE, "signal_driver.py")
    first, last = free_ports()
    for stage, sent, status_wanted in (("question", signal.SIGINT, 130), ("question", signal.SIGHUP, 130), ("running", signal.SIGINT, 130),
                                       ("running", signal.SIGKILL, -9)):
        env = {**os.environ, "SITE_LIB": LIB, "SITE_USER": str(USER) if USER else "", "SITE_FIRST": str(first), "SITE_LAST": str(last), "SITE_STAGE": stage,
               "SITE_BASE": base}
        p = subprocess.Popen([sys.executable, driver], stdout=subprocess.PIPE, text=True, env=env)
        got = ""
        while "READY" not in got:
            line = p.stdout.readline()
            if not line:
                break
            got += line
        was_open = listening(first)
        p.send_signal(sent)
        out, _ = p.communicate(timeout=20)
        name = sent.name
        time.sleep(0.5 if sent == signal.SIGKILL else 0)      # nothing waits for a killed setup's listener: it sees the link end
        check(f"{name} at the {stage} stage: the site was up, then setup ends ({status_wanted}) and the port closes with its listener",
              was_open and p.returncode == status_wanted and not listening(first), (was_open, p.returncode, got + out))
        if stage == "question":
            check(f"{name} before Proceed: nothing changed", not os.path.exists(os.path.join(base, "fabric")), list(os.walk(base))[:3])
        elif sent == signal.SIGKILL:
            shutil.rmtree(os.path.join(base, "fabric"), ignore_errors=True)
        else:
            check(f"{name} after Proceed: the terminal says the work goes on", "setup goes on" in out, out[-500:])
            shutil.rmtree(os.path.join(base, "fabric"), ignore_errors=True)

sys.exit(finish("flow_test"))
