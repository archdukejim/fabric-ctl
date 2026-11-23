#!/usr/bin/env python3
"""The console's Backups page in the dev preview (manual 1.3.7.9): the list with each bundle's check, Download, Back up
now, the schedule, Restore one section (a section picked, its warning in full, the key and the site's name typed) or the
whole bundle (started, then shown running with its log), Upload a bundle (streamed, its CSRF field first), each change a
job, saved or started; the refusals (passphrases that differ or too short, the site's name not typed, a key that is
not age1…, a path instead of a bundle's name, an upload not named or made as a bundle, or before its CSRF field); the page and every form refused to someone the sign-in did not find a
Domain Admin. The real agent's side is tests/sandbox/run.sh (the routes on a running install) and tests/samba/grants.py
(the Domain Admins check in a real DC).

    python3 tests/webui/test_backups.py
"""
import contextlib
import http.client
import os
import re
import subprocess
import sys
import time
import urllib.parse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
UX_WEB = os.path.join(REPO, "src", "ux", "web")
PORT = int(os.environ.get("WEBUI_DEV_PORT", "18885"))
START_WAIT = 15
FAILED = 0
BUNDLE = "fabric-fabric-20261121T150412Z-manual.fabric.tar"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:400]}"))


def req(method, path, form=None):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=20)
    body = urllib.parse.urlencode(form) if form is not None else None
    c.request(method, path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {})
    r = c.getresponse()
    return r.status, r.getheader("Location"), r.getheader("Content-Disposition"), r.read().decode()


def post(path, form):
    """POST a form as a browser does, following a 303: (status, location, the page shown after it)."""
    st, loc, _, page = req("POST", path, {"csrf": "dev", **form})
    if st == 303 and loc:
        page = req("GET", loc)[3]
    return st, loc or "", page


def upload(fields, filename, data):
    """POST the upload form as a browser does (multipart: the fields in order, then the file), following a 303."""
    boundary = "----fabrictest7MA4YWxkTrZu0gW"
    body = b"".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                    for k, v in fields)
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="{filename}"\r\n'
             "Content-Type: application/x-tar\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=20)
    c.request("POST", "/settings/backups/upload", body=body,
              headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    r = c.getresponse()
    st, loc, page = r.status, r.getheader("Location") or "", r.read().decode()
    if st == 303 and loc:
        page = req("GET", loc)[3]
    return st, loc, page


def flash(page):
    m = re.search(r'<p class="flash (ok|bad)" role="(?:status|alert)">(.*?)</p>', page, re.S)
    return (m.group(1) + ": " + m.group(2).replace("&#39;", "'")) if m else ""


@contextlib.contextmanager
def serve(bundle=None):
    global PORT
    PORT += 1
    args = [sys.executable, os.path.join(UX_WEB, "devserver.py"), "--port", str(PORT)]
    proc = subprocess.Popen(args + (["--as", bundle] if bundle else []), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        end = time.time() + START_WAIT
        while time.time() < end:
            try:
                req("GET", "/static/app.css")
                break
            except OSError:
                time.sleep(0.1)
        yield
    finally:
        proc.terminate()
        proc.wait(timeout=5)


with serve():
    print("--- the page")
    st, _, _, page = req("GET", "/settings/backups")
    # covers: web:get.settings.backups +
    check("the page renders: the bundles with their checks, Back up now, the schedule with its runs",
          st == 200 and BUNDLE in page and "checking" in page and "SHA-256 differs" in page
          and 'action="/settings/backups/now"' in page and "Next run" in page, st)
    check("its entry is under Settings in the navigation", 'href="/settings/backups"' in page)
    check("no script or inline style (the strict CSP)", "<script" not in page and "style=" not in page)
    st, _, disp, body = req("GET", f"/settings/backups/download/{BUNDLE}")
    check("Download: the bundle as an attachment under its own name",
          st == 200 and disp == f'attachment; filename="{BUNDLE}"', (st, disp))
    st = req("GET", "/settings/backups/download/..%2F..%2Fetc%2Fshadow")[0]
    check("negative: a path instead of a bundle's name is not found", st == 404, st)

    print("--- Back up now")
    # covers: web:post.settings.backups.now -
    st, loc, page = post("/settings/backups/now", {"passphrase": "twelve-chars-1", "passphrase_again": "twelve-chars-2"})
    check("passphrases that differ: refused, nothing made", "differ" in flash(page) and "/jobs/" not in loc, flash(page))
    st, loc, page = post("/settings/backups/now", {"passphrase": "short", "passphrase_again": "short"})
    check("a passphrase under 12 characters: refused by the agent, nothing made",
          "12 characters" in flash(page) and "/jobs/" not in loc, flash(page))
    # covers: web:post.settings.backups.now +
    st, loc, page = post("/settings/backups/now", {"passphrase": "twelve-chars-1", "passphrase_again": "twelve-chars-1"})
    check("a matching passphrase: a job, followed on its page, back to Backups from it",
          loc.startswith("/jobs/") and "Bundle made" in page and 'href="/settings/backups"' in page, (loc, page[-300:]))
    st, loc, page = post("/settings/backups/now", {"use_schedule": "1"})
    check("the schedule's public key instead: a job", loc.startswith("/jobs/") and "Bundle made" in page, loc)

    print("--- the schedule")
    # covers: web:post.settings.backups.schedule +
    st, loc, page = post("/settings/backups/schedule", {"action": "save", "time": "02:30", "keep": "10",
                                                        "public_key": "age1qyqszqgpqyqszqgp"})
    check("saved: said with the time and the count", "on 02:30, keeping 10" in flash(page), flash(page))
    # covers: web:post.settings.backups.schedule -
    st, loc, page = post("/settings/backups/schedule", {"action": "save", "time": "02:30", "keep": "10",
                                                        "public_key": "ssh-ed25519 AAAA"})
    check("a key that is not age1…: refused, nothing changed", "Refused, nothing changed" in flash(page)
          and "age1" in flash(page), flash(page))
    st, loc, page = post("/settings/backups/schedule", {"action": "off"})
    check("turned off: said, its runs no longer shown", "schedule is off" in flash(page) and "Next run" not in page,
          flash(page))

    print("--- Restore one section")
    page = req("GET", "/settings/backups?" + urllib.parse.urlencode({"restore": BUNDLE}))[3]
    check("a bundle picked: the whole restore offered, the sections offered, secrets only with the whole",
          "Restore the whole bundle…" in page and 'value="dns"' in page
          and re.search(r'value="secrets" required disabled', page), page[-400:])
    page = req("GET", "/settings/backups?" + urllib.parse.urlencode({"restore": BUNDLE, "section": "directory"}))[3]
    check("a section picked: its warning in full (what is replaced, lost, cannot be undone, what depends on it)",
          "Restoring directory replaces it" in page and "cannot be undone" in page and "Depends on it: dns, dhcp" in page
          and 'name="confirm"' in page, page[-400:])
    page = req("GET", "/settings/backups?" + urllib.parse.urlencode(
        {"restore": "fabric-fabric-20261120T030000Z-scheduled.fabric.tar"}))[3]
    check("negative: a bundle of another fabric version offers no section", "only into the same version" in page
          and 'name="section"' not in page)
    # covers: web:post.settings.backups.restore -
    st, loc, page = post("/settings/backups/restore", {"file": BUNDLE, "section": "dns", "key": "preview-pass-1",
                                                       "confirm": "wrong"})
    check("the site's name not typed: refused, back on the section's step", "site's name" in flash(page)
          and "section=dns" in loc and "/jobs/" not in loc, (loc, flash(page)))
    # covers: web:post.settings.backups.restore +
    st, loc, page = post("/settings/backups/restore", {"file": BUNDLE, "section": "dns", "key": "preview-pass-1",
                                                       "confirm": "lan"})
    check("typed: a job, its result naming the section and the bundle", loc.startswith("/jobs/")
          and f"dns restored from {BUNDLE}" in page and "Restore a section" in page, (loc, page[-300:]))

    print("--- Upload a bundle")
    page = req("GET", "/settings/backups")[3]
    check("the upload form: multipart, its CSRF field first, then the file",
          re.search(r'action="/settings/backups/upload" enctype="multipart/form-data"[^>]*>\s*<input type="hidden" '
                    r'name="csrf"', page) and 'name="bundle"' in page)
    NEW = "fabric-fabric-20261123T010000Z-manual.fabric.tar"
    # covers: web:post.settings.backups.upload +
    st, loc, page = upload([("csrf", "dev")], NEW, b"manifest.json" + b"\0" * 5000)
    check("a bundle uploaded: said with its name, now in the list", f"Uploaded {NEW}" in flash(page)
          and page.count(NEW) >= 1, flash(page))
    # covers: web:post.settings.backups.upload -
    st, loc, page = upload([("csrf", "dev")], NEW, b"manifest.json" + b"\0" * 10)
    check("negative: the same name again: refused, said", "already in the backups folder" in flash(page), flash(page))
    st, loc, page = upload([("csrf", "dev")], "holiday.tar", b"manifest.json")
    check("negative: a file not named as a bundle: refused, said", "not a bundle's" in flash(page), flash(page))
    st, loc, page = upload([("csrf", "dev")], "fabric-fabric-20261123T020000Z-manual.fabric.tar", b"PK\3\4 a zip")
    check("negative: a file that is not a bundle: refused, nothing listed", "no manifest.json" in flash(page)
          and "20261123T020000Z" not in page, flash(page))
    st = upload([("csrf", "wrong")], "fabric-fabric-20261123T030000Z-manual.fabric.tar", b"manifest.json")[0]
    check("negative: a wrong CSRF field: refused (403) before the file is read", st == 403, st)
    st = upload([], "fabric-fabric-20261123T030000Z-manual.fabric.tar", b"manifest.json")[0]
    check("negative: the file before any CSRF field: refused (403)", st == 403, st)

    print("--- Restore the whole bundle")
    page = req("GET", "/settings/backups?" + urllib.parse.urlencode({"restore": BUNDLE, "whole": "1"}))[3]
    check("its warning in full: what is replaced, lost, the safety bundle, the console going down, the move "
          "procedure instead", "Restoring the whole bundle replaces this install" in page and "is lost" in page
          and "safety bundle" in page and "goes down" in page and "4.2.4.8" in page
          and 'action="/settings/backups/reinstall"' in page, page[-600:])
    # covers: web:post.settings.backups.reinstall -
    st, loc, page = post("/settings/backups/reinstall", {"file": BUNDLE, "key": "preview-pass-1", "confirm": "nope"})
    check("the site's name not typed: refused, nothing started", "site's name" in flash(page)
          and "running now" not in page, flash(page))
    # covers: web:post.settings.backups.reinstall +
    st, loc, page = post("/settings/backups/reinstall", {"file": BUNDLE, "key": "preview-pass-1", "confirm": "lan"})
    check("typed: started, said; the page then shows it running with its log", "has started on the host" in flash(page)
          and "The last whole restore from the console" in page and "running now" in page, flash(page))
    page = req("GET", "/settings/backups?" + urllib.parse.urlencode({"restore": BUNDLE, "whole": "1"}))[3]
    check("negative: while it runs, no second whole restore is offered", "running already" in page
          and 'action="/settings/backups/reinstall"' not in page)

with serve("fabric-auditor"):
    print("--- not a Domain Admin")
    # covers: web:get.settings.backups -
    st, _, _, page = req("GET", "/settings/backups")
    check("the page is refused (403) and its entry is not shown", st == 403
          and 'href="/settings/backups"' not in req("GET", "/account")[3], st)
    check("a download is refused (403)", req("GET", f"/settings/backups/download/{BUNDLE}")[0] == 403)
    st = upload([("csrf", "dev")], "fabric-fabric-20261123T040000Z-manual.fabric.tar", b"manifest.json")[0]
    check("an upload refused (403)", st == 403, st)
    for form, data in (("now", {"passphrase": "twelve-chars-1", "passphrase_again": "twelve-chars-1"}),
                       ("reinstall", {"file": BUNDLE, "key": "k", "confirm": "lan"}),
                       ("schedule", {"action": "off"}),
                       ("restore", {"file": BUNDLE, "section": "dns", "key": "k", "confirm": "lan"})):
        st = req("POST", f"/settings/backups/{form}", {"csrf": "dev", **data})[0]
        check(f"{form} refused (403)", st == 403, st)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
