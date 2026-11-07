#!/usr/bin/env python3
"""Run inside the test browser image (decision 2.1.8.15): drive web-guided setup's site in real headless Chromium over its
DevTools pipe, as a person does, accepting every default. It does what a person's comparison does: it reads the certificate
the site serves, checks its fingerprint against the terminal's and only then goes past the warning. Pictures go to the
output folder. Not a test itself: browser_test.py and
tests/sandbox/web_guided.sh read what it prints.

    python3 site_probe.py <scenario.json>
        url, code, fingerprint, out (folder), answers {label's start: value}, secret (the first admin's password),
        width (default 1366), stop_at ("plan", "progress"), verify_new_certificate (bool), pictures (bool), resolve {name: address} (the browser's own DNS),
        finish_check (bool), check_with {stage: resolve} (the check again with such DNS), press_finish (default true)
    prints one JSON line per page or event: {"page", "title", "label", "wide", "text"} and last {"done": ...}
"""
import base64
import fcntl
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse


def _on_3_and_4(read_end, write_end):
    """Chromium's fds 3 and 4, by way of high numbers: a second browser's pipe may itself be on 3 or 4."""
    high = (fcntl.fcntl(read_end, fcntl.F_DUPFD, 20), fcntl.fcntl(write_end, fcntl.F_DUPFD, 20))
    os.dup2(high[0], 3)
    os.dup2(high[1], 4)


class Pipe:
    """The DevTools pipe: JSON messages, each ended by a NUL byte."""

    def __init__(self, resolve, profile):
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        args = ["chromium", "--headless", "--no-sandbox", "--disable-gpu", "--remote-debugging-pipe", "--no-first-run",
                "--disable-extensions", f"--user-data-dir={profile}"]
        if resolve:
            args.append("--host-resolver-rules=" + ",".join(f"MAP {n} {a}" for n, a in resolve.items()))
        self.proc = subprocess.Popen([*args, "about:blank"], pass_fds=(3, 4),
                                     preexec_fn=lambda: _on_3_and_4(r_in, w_out),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(r_in)
        os.close(w_out)
        self.w, self.r = os.fdopen(w_in, "wb"), os.fdopen(r_out, "rb")
        self.n, self.buf, self.events = 0, b"", []
        time.sleep(0.2)

    def send(self, method, params=None, session=None):
        self.n += 1
        msg = {"id": self.n, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        self.w.write(json.dumps(msg).encode() + b"\0")
        self.w.flush()
        want = self.n
        while True:
            m = self.read()
            if m.get("id") == want:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})
            self.events.append(m)

    def read(self):
        while b"\0" not in self.buf:
            chunk = self.r.read1(65536)
            if not chunk:
                raise RuntimeError("Chromium closed the pipe")
            self.buf += chunk
        raw, self.buf = self.buf.split(b"\0", 1)
        return json.loads(raw)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.w.close()
        self.r.close()


class Page:
    def __init__(self, scenario):
        self.s = scenario
        self.profile = tempfile.mkdtemp(prefix="site-probe-")
        self.shots = 0
        self.open_browser()

    def open_browser(self):
        self.cdp = Pipe(self.s.get("resolve"), self.profile)
        target = self.cdp.send("Target.createTarget", {"url": "about:blank"})["targetId"]
        self.session = self.cdp.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        for domain in ("Page", "Runtime", "Log", "Network"):
            self.cdp.send(f"{domain}.enable", session=self.session)
        # past the warning, as a person goes after comparing the fingerprint (run compares it first)
        self.cdp.send("Security.setIgnoreCertificateErrors", {"ignore": True}, session=self.session)
        width = int(self.s.get("width", 1366))
        self.cdp.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": 812 if width < 768 else 900,
                                                             "deviceScaleFactor": 1, "mobile": width < 768}, session=self.session)

    def reopen(self, resolve):
        """A browser with other DNS: the session's cookie carried over, as the same person's."""
        cookies = self.cdp.send("Network.getAllCookies", session=self.session)["cookies"]
        self.cdp.close()
        self.s["resolve"] = resolve
        self.open_browser()
        for c in cookies:
            self.cdp.send("Network.setCookie", {k: c[k] for k in ("name", "value", "path", "secure", "httpOnly", "sameSite") if k in c}
                          | {"url": self.s["url"]}, session=self.session)
        self.go(self.s["url"])
        self.settled()

    def js(self, text):
        out = self.cdp.send("Runtime.evaluate", {"expression": text, "returnByValue": True, "awaitPromise": True}, session=self.session)
        if "exceptionDetails" in out:
            raise RuntimeError(f"page script: {out['exceptionDetails']}")
        return out["result"].get("value")

    def errors(self):
        """Script errors and content-policy refusals since the last look: what a page must never have. A failed request
        of the finish's check is what that check is for."""
        found, keep = [], []
        for m in self.cdp.events:
            kind = m.get("method")
            if kind == "Runtime.exceptionThrown":
                found.append(str(m["params"]["exceptionDetails"])[:300])
            elif kind == "Log.entryAdded" and m["params"]["entry"].get("level") == "error":
                text = m["params"]["entry"].get("text", "")
                if "Content Security Policy" in text or "Refused" in text:
                    found.append(text[:300])
            else:
                keep.append(m)
        self.cdp.events = []
        return found

    def go(self, url):
        out = self.cdp.send("Page.navigate", {"url": url}, session=self.session)
        time.sleep(0.2)
        return out.get("errorText", "")

    def settled(self):
        """Wait for a page that has finished loading."""
        for _ in range(100):
            try:
                if self.js("document.readyState") == "complete":
                    return
            except RuntimeError:
                pass
            time.sleep(0.1)

    def report(self, name):
        info = json.loads(self.js("""JSON.stringify({title: document.title, label: (document.querySelector('label[for=value]')||{}).innerText||'',
          wide: document.documentElement.scrollWidth > window.innerWidth + 1, scroll: document.documentElement.scrollWidth,
          text: document.body.innerText.slice(0, 6000), broken: [...document.images].filter(i => !i.complete || !i.naturalWidth).map(i => i.src),
          css: !!(document.styleSheets[0] && document.styleSheets[0].cssRules.length)})"""))
        info["page"] = name
        info["errors"] = self.errors()
        print(json.dumps(info), flush=True)
        if self.s.get("pictures"):
            data = self.cdp.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True}, session=self.session)["data"]
            self.shots += 1
            with open(os.path.join(self.s["out"], f"{self.shots:02d}-{name}-{self.s.get('width', 1366)}.png"), "wb") as f:
                f.write(base64.b64decode(data))
        return info

    def fill_and_submit(self, value, selector="form[action='/answer'] button"):
        self.js("document.getElementById('value').value = " + json.dumps(value))
        self.click(selector)

    def click(self, selector):
        self.js(f"document.querySelector({json.dumps(selector)}).click()")
        time.sleep(0.3)
        self.settled()


def served_certificate(url):
    """The certificate the site serves: what a person opens from the address bar."""
    parts = urllib.parse.urlsplit(url)
    with ssl._create_unverified_context().wrap_socket(socket.create_connection((parts.hostname, parts.port), timeout=10)) as s:
        return s.getpeercert(True)


def fingerprint(der):
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, 64, 2))


def run(s):
    url = s["url"]
    der = served_certificate(url)
    if fingerprint(der) != s["fingerprint"]:
        print(json.dumps({"done": False, "why": "the served certificate is not the terminal's", "got": fingerprint(der)}), flush=True)
        return 1
    page = Page(s)
    error = page.go(url)
    if error:
        print(json.dumps({"done": False, "why": f"could not open the site: {error}"}), flush=True)
        return 1
    page.settled()
    page.report("code")
    page.js("document.getElementById('code').value = " + json.dumps(s["code"]))
    page.click("form[action='/code'] button")
    secrets_given = 0
    seen = stuck = 0
    end = time.time() + float(s.get("seconds", 3600))
    while time.time() < end:
        page.settled()
        kind = page.js("""(document.querySelector("form[action='/answer'] button[value=p]") ? 'plan' :
           document.querySelector("form[action='/answer'] #value") ? 'question' :
           document.querySelector("form[action='/answer'] button") ? 'buttons' :
           document.getElementById('log') && document.title.startsWith('Installing') ? 'progress' :
           document.title.startsWith('Setup stopped') ? 'failed' :
           document.title.startsWith('A new certificate') ? 'restarting' :
           document.title.startsWith('fabric is installed') ? 'finish' :
           document.title.startsWith('The site has closed') ? 'closed' : 'other')""")
        if kind == "question":
            seen += 1
            info = page.report(f"q{seen}")
            kind_secret = page.js("document.getElementById('value').type") == "password"
            label = info["label"]
            value = next((v for k, v in s.get("answers", {}).items() if label.startswith(k)), None)
            if kind_secret:
                value, secrets_given = s["secret"], secrets_given + 1
            elif value is None:
                value = page.js("document.getElementById('value').value")      # every default accepted
            page.fill_and_submit(value)
        elif kind == "buttons":
            seen += 1
            page.report(f"q{seen}")
            page.click("form[action='/answer'] button")      # the default's button
        elif kind == "plan":
            page.report("plan")
            if s.get("stop_at") == "plan":
                print(json.dumps({"done": True, "stopped": "plan"}), flush=True)
                page.cdp.close()
                return 0
            page.click("form[action='/answer'] button[value=p]")
        elif kind == "progress":
            if not getattr(page, "progress_seen", False):
                page.progress_seen = True
                page.report("progress")
                if s.get("stop_at") == "progress":
                    print(json.dumps({"done": True, "stopped": "progress"}), flush=True)
                    page.cdp.close()
                    return 0
            if s.get("watch_log_for"):
                lines = page.js("document.getElementById('log').textContent")
                if s["watch_log_for"] in lines:
                    print(json.dumps({"event": "live log", "saw": s["watch_log_for"]}), flush=True)
                    s["watch_log_for"] = ""
            time.sleep(1)
        elif kind == "failed":
            page.report("failed")
            print(json.dumps({"done": False, "why": "setup stopped", "text": page.js("document.body.innerText")[-3000:]}), flush=True)
            page.cdp.close()
            return 1
        elif kind == "restarting":
            page.report("restarting")
            # the new certificate: the person compares it and continues, as with the first
            time.sleep(float(s.get("restart_wait", 5)))
            der = served_certificate(url)
            print(json.dumps({"event": "new certificate", "fingerprint": fingerprint(der)}), flush=True)
            page.go(url)
        elif kind == "finish":
            page.report("finish")
            if s.get("verify_new_certificate"):
                print(json.dumps({"event": "verifies against the root", **verify_against_root(url)}), flush=True)
            if s.get("finish_check"):
                finish_checks(page, s)
            if s.get("press_finish", True):
                page.click("form[action='/finish'] button")
                page.report("closed")
                print(json.dumps({"done": True}), flush=True)
            else:
                print(json.dumps({"done": True, "stopped": "finish"}), flush=True)
            page.cdp.close()
            shutil.rmtree(page.profile, ignore_errors=True)
            return 0
        elif kind == "closed":
            page.report("closed")
            print(json.dumps({"done": False, "why": "the site closed"}), flush=True)
            return 1
        else:
            if "certificate" in (page.js("document.body.innerText") or "").lower() and "chrome-error" in page.js("location.href"):
                print(json.dumps({"event": "certificate refused"}), flush=True)
                return 1
            stuck += 1
            if stuck % 20 == 1:               # what the page shows, for a run that times out here
                print(json.dumps({"event": "waiting", "href": page.js("location.href"), "text": page.js("document.body.innerText")[:600]}), flush=True)
            time.sleep(0.5)
    print(json.dumps({"done": False, "why": "timed out"}), flush=True)
    return 1


def verify_against_root(url):
    """What a browser that trusts the offered root does: a verified connection to this address, names and all."""
    parts = urllib.parse.urlsplit(url)
    plain = ssl.create_default_context()
    plain.check_hostname, plain.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((parts.hostname, parts.port), timeout=10) as raw, plain.wrap_socket(raw) as tls:
            tls.sendall(f"GET /root-ca.crt HTTP/1.1\r\nHost: {parts.netloc}\r\nConnection: close\r\n\r\n".encode())
            answer = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                answer += chunk
        root = answer.split(b"\r\n\r\n", 1)[1].decode()
        strict = ssl.create_default_context(cadata=root)
        with socket.create_connection((parts.hostname, parts.port), timeout=10) as raw:
            with strict.wrap_socket(raw, server_hostname=parts.hostname):
                return {"ok": True}
    except (OSError, ssl.SSLError, IndexError, ValueError) as e:
        return {"ok": False, "why": str(e)}


def press_check(page):
    page.js("document.getElementById('check-button').scrollIntoView()")
    page.click("#check-button")
    for _ in range(120):
        text = page.js("document.getElementById('check-result').textContent")
        if text and not text.startswith("Checking"):
            return text
        time.sleep(0.5)
    return text


def finish_checks(page, s):
    """The finish's check, in a real browser: each of its answers."""
    print(json.dumps({"event": "check", "stage": s.get("check_stage", "first"), "text": press_check(page)}), flush=True)
    for name, resolve in (s.get("check_with") or {}).items():
        page.reopen(resolve)
        print(json.dumps({"event": "check", "stage": name, "text": press_check(page)}), flush=True)


if __name__ == "__main__":
    with open(sys.argv[1]) as handle:
        sys.exit(run(json.load(handle)))
