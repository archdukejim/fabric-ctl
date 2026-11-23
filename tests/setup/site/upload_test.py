#!/usr/bin/env python3
"""The setup site's Restore from a backup with an upload (manual 1.3.7.10), through a real listener process (as uid
649 when run as root, as the product does), real TLS and sockets: the first choice, the bundle's question with its
upload form, the file streamed by the listener into its folder, then taken by root into the backups folder and checked;
the refusals (no session, a wrong Origin, a stale token, an upload when the bundle is not being asked) keep nothing.
The bundle's own check and the key's are stood in for (tests/backup/restore_test.py makes real ones).

    sudo python3 tests/setup/site/upload_test.py
"""
import http.client
import os
import re
import ssl
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from support import Browser, check, finish, free_ports, label_of, listener_lib  # noqa: E402
import fabriclib.setup.site.ask_restore as ar  # noqa: E402
import fabriclib.setup.site.guided_site as gs  # noqa: E402
from fabriclib.backup.receive_upload import receive_upload  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.site.ask_start import ask_start  # noqa: E402
from fabriclib.setup.site.open_upload_dir import open_upload_dir  # noqa: E402

LIB, USER = listener_lib()
NET = {"hostname": "fabric-test", "host_ip": "127.0.0.1", "lan_gateway": "127.0.0.2", "lan_cidr": "127.0.0.0/8",
       "interface": "lo"}
gs.detect_network = lambda: NET
gs.open_site_port = lambda port, cidr: False
NAME = "fabric-fabric-1-20261122T030000Z-uninstall.fabric.tar"
DATA = os.urandom(3 << 20)
MANIFEST = {"host": "fabric-1", "domain": "lab.test", "host_ip": "10.0.0.5", "lan_cidr": "10.0.0.0/24",
            "lan_gateway": "10.0.0.1", "made": "2026-11-22T03:00:00Z", "fabric_version": "0.10.1",
            "opened_by": "passphrase", "sections": [{"name": "dns"}]}
ar.check_bundle = lambda path: dict(MANIFEST)
checked = []
ar._take_upload.__defaults__ = (lambda name, pieces, folder: receive_upload(
    name, pieces, folder=folder, check=lambda part: checked.append(open(part, "rb").read() == DATA)),)
if USER is None:                         # not root: the listener runs as this user, so its folder is this user's
    ar.open_upload_dir = lambda path: open_upload_dir(path, uid=os.getuid())


class Term:
    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text += text

    def flush(self):
        pass

    def code(self):
        return re.findall(r"code:\s+(\S+)", self.text)[-1]


def multipart(browser, fields, file_name, data, origin="same"):
    """POST /upload as a browser sends the page's form: the hidden fields, then the file, in that order."""
    boundary = "----fabrictest" + os.urandom(6).hex()
    body = b"".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                    for k, v in fields.items())
    body += (f'--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="{file_name}"\r\n'
             "Content-Type: application/x-tar\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    c = http.client.HTTPSConnection(browser.host, browser.port, timeout=60, context=browser.tls)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if browser.cookie:
        headers["Cookie"] = browser.cookie
    if origin:
        headers["Origin"] = f"https://{browser.host}:{browser.port}" if origin == "same" else origin
    try:
        c.request("POST", "/upload", body=body, headers=headers)
        r = c.getresponse()
        text = r.read().decode("utf-8", "replace")
    except (ssl.SSLError, ConnectionError) as exc:    # refused before the file was read: the connection closed
        return None, str(exc)
    finally:
        c.close()
    return r.status, text


def page_until(browser, words, wait=10):
    end = time.monotonic() + wait
    while time.monotonic() < end:
        status, page, _ = browser.get()
        if words in label_of(page) or words in page:
            return page
        time.sleep(0.2)
    return page


base = tempfile.mkdtemp()
os.chmod(base, 0o755)                   # the listener's uid reaches its folder in it
backups, uploads = os.path.join(base, "backups"), os.path.join(base, "lib", "upload")
first, last = free_ports()
term = Term()
ctx = SetupContext(deploy_base=os.path.join(base, "opt"))
site = gs.GuidedSite(ctx, term=term, first=first, last=last, record=os.path.join(base, "site-port"), lib_dir=LIB,
                     user=USER, grace=0.2, attach=os.path.join(base, "attach.sock"), upload_dir=uploads)
site.open()
box = {}


def setup_side():
    try:
        box["start"] = ask_start()
        box["out"] = ar.ask_restore(ctx, "0.10.1", folder=backups, bundles=lambda f: [],
                                    check=lambda *a: None, upload_dir=uploads)
    except (SetupError, SystemExit) as exc:
        box["stopped"] = str(exc)


threading.Thread(target=setup_side, daemon=True).start()
browser = Browser(site.port)
status, page, _ = browser.post("/code", {"code": term.code()})
page = page_until(browser, "How do you want to set fabric up?")
check("the first choice: New install and Restore from a backup, as buttons",
      'value="n"' in page and 'value="r"' in page and "Restore from a backup" in page, page[-1500:])
browser.answer(page, "r")
page = page_until(browser, "The bundle")
check("the bundle's question offers an upload, its token before the file",
      'action="/upload"' in page and 'enctype="multipart/form-data"' in page
      and page.index('name="csrf"', page.index('action="/upload"')) < page.index('type="file"'), page[-2000:])
fields = {"csrf": browser.field(page, "csrf"), "seq": browser.field(page, "seq")}

# covers: site:post.upload -
stranger = Browser(site.port)
status, text = multipart(stranger, fields, NAME, DATA)
check("negative: no session: refused (403, or the connection closed unread), nothing in the upload folder",
      status in (403, None) and not os.listdir(uploads),
      (status, os.listdir(uploads)))
status, text = multipart(browser, fields, NAME, DATA, origin="https://evil.example")
check("negative: another site's form (Origin): refused, nothing kept", status in (403, None)
      and not os.listdir(uploads),
      (status, text[-300:]))
status, text = multipart(browser, dict(fields, csrf="stale"), NAME, DATA)
check("negative: a stale token, signed in: the refusal page itself (the rest read and dropped), nothing kept",
      status == 403 and "stale" in text and not os.listdir(uploads),
      (status, text[-300:]))
status, text = multipart(browser, fields, "holiday.tar", DATA)
check("negative: a file not named as a bundle: refused, saying so, nothing kept",
      status == 400 and "not a bundle" in text and not os.listdir(uploads), (status, text[-300:]))

# covers: site:post.upload +
status, text = multipart(browser, fields, NAME, DATA)
check("the upload: accepted, and the page goes on", status == 303, (status, text[-300:]))
page = page_until(browser, "passphrase")
check("root took it: in the backups folder whole, checked, the listener's folder gone, the key asked next",
      open(os.path.join(backups, NAME), "rb").read() == DATA and checked == [True] and not os.path.exists(uploads)
      and "passphrase" in label_of(page), (checked, os.path.exists(uploads), label_of(page)))
check("the bundle's name and manifest are in the page's notes", NAME in page and "lab.test" in page, page[-2000:])
status, text = multipart(browser, dict(fields, seq=browser.field(page, "seq")), NAME.replace("1122", "1123"), DATA)
check("negative: an upload when the bundle is not being asked: 409, nothing kept",
      status == 409 and not os.path.exists(os.path.join(backups, NAME.replace("1122", "1123"))), (status, text[-300:]))

browser.answer(page, "a passphrase for this test")
for label in ("The host's address", "Its subnet", "The subnet's gateway"):    # the bundle's kept
    page = page_until(browser, label)
    check(f"{label}: the bundle's own as its default", label in label_of(page) and browser.field(page, "value"),
          label_of(page))
    browser.answer(page, browser.field(page, "value"))
page = page_until(browser, "Proceed with this plan?")
browser.post("/answer", {"csrf": browser.field(page, "csrf"), "seq": browser.field(page, "seq"), "value": "q"})
time.sleep(1)
check("Cancel at the plan: stopped, nothing restored", "nothing was restored" in box.get("stopped", ""), box)
site.close()
finish("upload_test")
