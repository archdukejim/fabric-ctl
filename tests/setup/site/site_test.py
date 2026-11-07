"""Web-guided setup's site (manual 1.3.6.8), its trust, refusals and limits, with a real listener process, real TLS and
real sockets; the questions are Guided's real ones (collect_vars and its checks, ask_first_admin, choose_plan), only
the host's network and the plan's host changes stood in for, since no host changes before Proceed.
    python3 tests/setup/site/site_test.py"""
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import Browser, check, finish, free_ports, label_of, listener_lib  # noqa: E402

import fabriclib.setup.site.guided_site as gs  # noqa: E402
import fabriclib.setup.collect_vars as cv  # noqa: E402
from fabriclib.common.ask import ask  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.constants import SESSION_QUIET_SECONDS  # noqa: E402
from fabriclib.setup.site.pick_port import pick_port  # noqa: E402
from fabriclib.setup.site.question_view import question_view  # noqa: E402

LIB, USER = listener_lib()
NET = {"hostname": "fabric-test", "host_ip": "127.0.0.1", "lan_gateway": "127.0.0.2", "lan_cidr": "127.0.0.0/8",
       "interface": "lo"}
gs.detect_network = lambda: NET
cv.detect_network = lambda: NET
cv.network_problem = lambda data: ""     # this machine's addresses are not the test's business
gs.open_site_port = lambda port, cidr: False


class Term:
    """The terminal, kept to read."""

    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass

    def code(self):
        return re.findall(r"code:\s+(\S+)", self.text)[-1]


def new_site(base, **options):
    first, last = free_ports()
    term = Term()
    ctx = SetupContext(deploy_base=base)
    record = os.path.join(base, "site-port")
    site = gs.GuidedSite(ctx, term=term, first=first, last=last, record=record, lib_dir=LIB, user=USER, grace=0.2, **options)
    site.open()
    return site, term, Browser(site.port), record


def in_thread(fn):
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as e:
            box["raised"] = e
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def listening(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


with tempfile.TemporaryDirectory() as base:
    target = os.path.join(base, "fabric")

    # ---- the site, its certificate and the code ----
    site, term, browser, record = new_site(base)
    port = site.port
    check("the terminal prints the URL, the code and the fingerprint",
          f"https://127.0.0.1:{port}/" in term.text and "One-time code" in term.text and site.fingerprint in term.text, term.text)
    check("the terminal says a temporary certificate is in use, and what the check protects against",
          "temporary certificate is in use" in term.text and "intercept" in term.text, term.text)
    raw = ssl._create_unverified_context()
    with raw.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5)) as s:
        der = s.getpeercert(True)
        check("TLS 1.2 or newer", s.version() in ("TLSv1.2", "TLSv1.3"), s.version())
    pem = ssl.DER_cert_to_PEM_cert(der)
    from fabriclib.setup.site.certificate_fingerprint import certificate_fingerprint  # noqa: E402
    check("the fingerprint printed is the certificate served", certificate_fingerprint(pem) == site.fingerprint)
    out = subprocess.run(["openssl", "x509", "-noout", "-dates", "-ext", "subjectAltName"], input=pem, capture_output=True, text=True).stdout
    check("the certificate names the host's address and name", "127.0.0.1" in out and "fabric-test" in out, out)
    days = subprocess.run(["openssl", "x509", "-noout", "-checkend", str(86400 + 300)], input=pem, capture_output=True, text=True)
    check("the certificate lasts one day", days.returncode != 0, days.stdout)
    pid = site.process.pid
    uid = os.stat(f"/proc/{pid}").st_uid
    if USER:
        check("the listener runs as nobody, not root", uid == 65534, uid)
        with open(f"/proc/{pid}/status") as f:
            status = f.read()
        check("the listener holds no capabilities and can gain no privilege",
              re.search(r"CapEff:\s+0+\n", status) and re.search(r"NoNewPrivs:\s+1", status), status)
    else:
        print("SKIP the listener's account (not root: run the suite as root)")
    check("nothing holds the certificate on a disk: no file named for it in the install folder", not os.path.exists(target) or
          not any("key" in n or "pem" in n for _, _, ns in os.walk(target) for n in ns))

    # ---- refusals before the code: covers: site:post.code - ----
    status, page, r = browser.get()
    check("no session: the code page, with the fingerprint to compare", status == 200 and site.fingerprint in page and 'action="/code"' in page, page[:300])  # covers: site:get.home +
    check("the page says the certificate is temporary (the relaxation visible)", "Temporary certificate in use" in page, page[:500])
    headers = dict(r.getheaders())
    check("the page's headers: CSP, nosniff, no framing, no HSTS",
          "default-src 'none'" in headers.get("Content-Security-Policy", "") and headers.get("X-Content-Type-Options") == "nosniff"
          and headers.get("X-Frame-Options") == "DENY" and "Strict-Transport-Security" not in headers, headers)
    status, page, _ = browser.get("/nope")
    check("an unknown address: refused, saying so", status == 404 and "no such page" in page, page[:200])
    status, _, _ = browser.get("/events")
    check("the live stream without a session: refused", status == 401, status)  # covers: site:get.events -
    status, page, _ = browser.post("/answer", {"csrf": "x", "seq": "1", "value": "x"})
    check("an answer without a session: refused", status == 403 and "session" in page, page[:300])  # covers: site:post.answer -
    status, page, _ = browser.post("/code", {"code": term.code()}, origin="https://evil.example")
    check("a right code with a wrong Origin: refused, naming it, and no session", status == 403 and "evil.example" in page and "Nothing was changed" in page and not browser.cookie, page[:300])  # covers: site:post.code -
    status, page, _ = browser.post("/code", {"code": term.code()}, origin=None)
    check("no Origin at all: refused", status == 403 and not browser.cookie, page[:300])

    # wrong code and the lockout
    first_code = term.code()
    for n in range(1, 5):
        status, page, _ = browser.post("/code", {"code": "WRONG-CODE-0000"})
        check(f"wrong code {n}: refused, saying how many tries are left", status == 403 and f"{5 - n} tries left" in page, page[:400])
    status, page, _ = browser.post("/code", {"code": "WRONG-CODE-0000"})
    second_code = term.code()
    check("the fifth wrong code replaces it, and the terminal prints the new one", status == 403 and "new one" in page and second_code != first_code, term.text[-300:])
    check("the code is printed on the terminal only: never in a page", second_code not in page and first_code not in page)
    status, page, _ = browser.post("/code", {"code": first_code})
    check("the replaced code no longer opens anything", status == 403 and not browser.cookie, page[:300])
    status, page, _ = browser.request("POST", "/code", {"code": "A" * 70000})
    check("a body past the limit: refused", status == 413, status)

    # ---- the session ----
    status, page, _ = browser.post("/code", {"code": second_code.lower()})
    cookie = browser.cookie
    check("the right code opens a session (typed in any case)", status == 303 and "__Host-fabric-setup=" in cookie, (status, cookie))  # covers: site:post.code +

    other = Browser(port)
    status, page, _ = other.post("/code", {"code": second_code})
    check("a second browser with the right code: refused and told why", status == 409 and "Another browser" in page and not other.cookie, page[:400])  # covers: site:get.home -

    # the questions: Guided's own, real checks
    ctx = site.ctx

    def run_questions():
        ctx.vars = {}
        cv.collect_vars(ctx)
        return ctx.vars

    t, box = in_thread(run_questions)
    order = []
    bad_seen = {}
    bad = {"DNS domain": "not a domain", "This host's name": "bad.name", "This host's LAN address": "999.1.1.1",
           "LAN subnet": "not-a-cidr", "LAN gateway": "nope", "Organisation's name": "<bad>", "Windows (AD) domain": "x.local"}
    good = {"DNS domain": "lan.example", "This host's name": "fabric-test", "This host's LAN address": "",
            "LAN subnet": "", "LAN gateway": "", "Organisation's name": "Example", "Windows (AD) domain": ""}
    deadline = time.time() + 60
    while t.is_alive() and time.time() < deadline:
        status, page, _ = browser.get()
        if 'action="/answer"' not in page:
            time.sleep(0.05)
            continue
        label = label_of(page)
        key = next((k for k in bad if label.startswith(k)), None)
        if key is None:
            check("an unexpected question", False, label)
            break
        if key not in bad_seen:
            bad_seen[key] = True
            browser.answer(page, bad[key])
            status, again, _ = browser.get()
            why = "not a valid" in again or "a domain of two labels" in again or "two labels" in again
            check(f"a bad answer to '{key}': asked again, saying why, as the terminal does", label_of(again).startswith(key) and why, again[:900])
            page = again
        order.append(key)
        browser.answer(page, good[key] or browser.field(page, "value") or "")
        time.sleep(0.05)
    t.join(10)
    check("Guided's questions all came through the page, in order", order[:2] == ["DNS domain", "This host's name"] and "Windows (AD) domain" in order, order)
    check("the answers reached setup's settings", box.get("value", {}).get("domain") == "lan.example" and box["value"].get("ad_domain"), box)

    # permanent mark and the question's shape
    view = question_view("setup.vars.domain", "  DNS domain (e.g. home.arpa) \x1b[93m⚠ Permanent\x1b[0m [home.arpa]: ", False)
    check("a permanent choice is marked, its default the field's value, its colour gone",
          view["permanent"] and view["default"] == "home.arpa" and "\x1b" not in view["label"] and "⚠" not in view["label"], view)
    view = question_view("setup.consent.x", "\n  Allow it? [Y/n] ", False)
    check("yes or no: two buttons, the default first", view["choices"][0][0] == "y" and view["label"] == "Allow it?", view)

    # the plan: Proceed, Cancel; the menu refused; declined consent changes nothing
    def plan():
        return ask("setup.plan", "\n  [P]roceed (allows the host changes listed), [M]enu, or [Q]uit? ")

    print("  the plan text\n    - a host change")
    t, box = in_thread(plan)
    deadline = time.time() + 15
    page = ""
    while time.time() < deadline:
        status, page, _ = browser.get()
        if "Proceed" in page and 'value="p"' in page:
            break
        time.sleep(0.05)
    check("the plan shows what was printed before it, with one confirmation", "the plan text" in page and "a host change" in page and 'value="p"' in page and 'value="q"' in page, page[:800])
    check("the plan offers no menu: Advanced stays in the terminal", 'value="m"' not in page)
    status, stale, _ = browser.post("/answer", {"csrf": "not-the-token", "seq": browser.field(page, "seq"), "value": "p"})
    check("a stale CSRF token: refused, saying so, nothing happened", status == 403 and "stale" in stale and t.is_alive(), stale[:300])  # covers: site:post.cancel -
    status, wrong, _ = browser.post("/answer", {"csrf": browser.field(page, "csrf"), "seq": browser.field(page, "seq"), "value": "p"}, origin="https://evil.example")
    check("the plan's Proceed from another site's page: refused, nothing happened", status == 403 and t.is_alive(), wrong[:300])
    browser.answer(page, "m")
    time.sleep(0.2)
    status, page, _ = browser.get()
    check("the menu's answer posted anyway: refused, saying why, the plan asked again", "the menu stays in the terminal" in page and 'value="p"' in page and t.is_alive(), page[:800])  # covers: site:post.answer +
    check("the refused plan keeps its text", "the plan text" in page, page[:800])
    status, _, _ = browser.post("/cancel", {"csrf": browser.field(page, "csrf")})
    t.join(10)
    check("Cancel: setup is told, as Quit", isinstance(box.get("raised"), SystemExit) and "cancelled" in str(box["raised"]), box)  # covers: site:post.cancel +
    written = os.path.exists(os.path.join(target, "config", "fabric.yaml"))
    check("(the questions did save settings as they went)", written)
    site.close()
    check("after Cancel: nothing changed: the install folder is as it was found", not os.path.exists(target), list(os.walk(target)))
    check("after Cancel: the port is closed", not listening(port))
    check("after Cancel: the listener has gone", site.process is None and not os.path.exists(f"/proc/{pid}"), pid)
    check("after Cancel: the record is gone", not os.path.exists(record))
    check("the terminal says the site stopped", "The setup site has stopped" in term.text, term.text[-200:])

    # ---- the idle limit ----
    site, term, browser, record = new_site(base, idle=1)
    port = site.port
    try:
        ask("test.q", "A question: ")
        check("the idle limit", False)
    except SetupError as e:
        check("idle past the limit: refused, saying so and how to start again", "idle" in str(e) and "sudo fabricctl setup" in str(e), e)
    site.close(str("closed"))
    check("idle: the port is closed and nothing changed", not listening(port) and not os.path.exists(target))

    # ---- a listener that dies ----
    site, term, browser, record = new_site(base)
    port = site.port
    site.process.kill()
    try:
        ask("test.q", "A question: ")
        check("a dead listener", False)
    except SetupError as e:
        check("the listener dying stops setup, saying so, with nothing changed", "ended" in str(e), e)
    site.close()
    check("then the port is closed", not listening(port))

    # ---- the code again after a quiet session: reconnecting ----
    site, term, browser, record = new_site(base)
    port = site.port
    code = term.code()
    browser.post("/code", {"code": code})
    old_page_csrf = None
    t, box = in_thread(lambda: ask("test.q", "A question [yes]: ", "yes"))
    time.sleep(0.2)
    status, page, _ = browser.get()
    check("a default in brackets is the field's value", 'value="yes"' in page, page[:800])
    old_page_csrf = browser.field(page, "csrf")
    # the browser goes away: its cookie gone, it has been quiet long enough
    site.keeper.seen -= SESSION_QUIET_SECONDS + 1
    second = Browser(port)
    status, _, _ = second.post("/code", {"code": code})
    check("connection lost before Proceed: the same code reconnects once the old session is quiet", status == 303 and second.cookie, status)
    status, again, _ = browser.get()
    check("the old browser's session is over", 'action="/code"' in again, again[:300])
    status, _, _ = second.post("/answer", {"csrf": old_page_csrf, "seq": "1", "value": "x"})
    check("the old page's CSRF token is stale now", status == 403, status)
    status, page, _ = second.get()
    second.answer(page, "")
    t.join(5)
    check("the new browser answers, Enter taking the default", box.get("value") == "yes", box)
    site.close()

    # ---- ports: collisions, real sockets ----
    first, last = free_ports(3)
    held = []
    for p in range(first, last):
        s = socket.socket()
        s.bind(("0.0.0.0", p))
        s.listen(1)
        held.append(s)
    sock, got, found = pick_port(first, last, holder=lambda p: "testprog (pid 7)")
    check("the first ports taken: the next is used, saying what held them", got == last and len(found) == 2 and "testprog" in found[0], found)
    sock.close()
    s = socket.socket()
    s.bind(("0.0.0.0", last))
    s.listen(1)
    held.append(s)
    try:
        pick_port(first, last, holder=lambda p: "testprog (pid 7)")
        check("all ports taken", False)
    except SetupError as e:
        check("all ports taken: refused, saying what holds the first and offering --terminal, nothing changed",
              "testprog" in str(e) and "--terminal" in str(e) and "Nothing was changed" in str(e), e)
    for s in held:
        s.close()

    # ---- the firewall in the way, consent declined ----
    def declined(port, cidr):
        raise SetupError("without TCP open a browser cannot reach the setup site. sudo fabricctl setup --terminal. Nothing was changed.")
    saved = gs.open_site_port
    gs.open_site_port = declined
    before = set(os.listdir(base))
    try:
        new_site(base)
        check("a declined firewall question", False)
    except SetupError as e:
        check("a declined firewall question: refused, nothing changed", "--terminal" in str(e) and set(os.listdir(base)) == before, e)
    gs.open_site_port = saved

sys.exit(finish("site_test"))
