"""What the web-guided setup tests share: a real site (real listener process, real TLS, real sockets) driven as a browser
drives it, over http.client. Not a test itself. The listener's code is copied to a world-readable folder when run as
root, because it runs as nobody and a checkout's parents may not be readable (a CI runner's home)."""
import html
import http.client
import os
import re
import shutil
import socket
import ssl
import sys
import tempfile
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REPO, "src"))

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    # the real stdout: while a site is open, sys.stdout is what the next question's page will show
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:1200]}"), flush=True, file=sys.__stdout__)


def finish(script):
    print(f"{script}: {PASS} passed, {FAIL} failed", flush=True)
    return 1 if FAIL else 0


def free_ports(count=3):
    """A run of free TCP ports, starting high enough to be nothing's."""
    for first in range(28443, 40000, 50):
        socks = []
        try:
            for port in range(first, first + count):
                s = socket.socket()
                s.bind(("0.0.0.0", port))
                socks.append(s)
            return first, first + count - 1
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free ports")


def listener_lib():
    """(lib_dir, user) for GuidedSite. As root: a readable copy, run as nobody, as the product does. Otherwise this user."""
    source = os.path.join(REPO, "src")
    if os.geteuid() != 0:
        return source, None
    top = tempfile.mkdtemp(prefix="fabric-site-lib-", dir="/tmp")
    os.chmod(top, 0o755)
    for rel in ("fabriclib/__init__.py", "fabriclib/setup/__init__.py", "fabriclib/setup/site/__init__.py"):
        os.makedirs(os.path.dirname(os.path.join(top, rel)), exist_ok=True)
        shutil.copy(os.path.join(source, rel), os.path.join(top, rel))
    shutil.copytree(os.path.join(source, "fabriclib/setup/site/listener"), os.path.join(top, "fabriclib/setup/site/listener"))
    for kind in ("templates", "static"):      # as packaging/deb/assemble-tree.sh lays them out
        shutil.copytree(os.path.join(REPO, kind, "setup-site"), os.path.join(top, "setup-site"), dirs_exist_ok=True)
    for folder, _, names in os.walk(top):
        os.chmod(folder, 0o755)
        for name in names:
            os.chmod(os.path.join(folder, name), 0o644)
    return top, "nobody"


class Browser:
    """One browser: its own cookie jar; refuses nothing about the certificate unless given a CA to verify against."""

    def __init__(self, port, cafile=None, host="127.0.0.1"):
        self.port, self.host, self.cookie = port, host, ""
        self.tls = ssl.create_default_context(cafile=cafile) if cafile else ssl._create_unverified_context()

    def request(self, verb, path, form=None, origin="same", headers=None):
        c = http.client.HTTPSConnection(self.host, self.port, timeout=30, context=self.tls)
        h = dict(headers or {})
        body = None
        if self.cookie:
            h["Cookie"] = self.cookie
        if verb == "POST":
            h["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(form or {})
            if origin == "same":
                h["Origin"] = f"https://{self.host}:{self.port}"
            elif origin:
                h["Origin"] = origin
        c.request(verb, path, body=body, headers=h)
        r = c.getresponse()
        text = r.read().decode("utf-8", "replace")
        found = r.getheader("Set-Cookie")
        if found:
            self.cookie = found.split(";")[0]
        r.close()
        c.close()
        return r.status, text, r

    def get(self, path="/"):
        return self.request("GET", path)

    def post(self, path, form=None, origin="same"):
        return self.request("POST", path, form, origin)

    def field(self, page, name):
        m = re.search(rf'name="{name}" value="([^"]*)"', page)
        return m.group(1) if m else None

    def answer(self, page, value):
        """Post a question's form as its page gives it."""
        return self.post("/answer", {"csrf": self.field(page, "csrf"), "seq": self.field(page, "seq"), "value": value})


def label_of(page):
    m = re.search(r'<label for="value">(.*?)</label>', page, re.S)
    return html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else ""
