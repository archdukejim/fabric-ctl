#!/usr/bin/env python3
"""The setup site's upload, as the listener saves it (listener/save_upload, listener/multipart_reader; manual 1.3.7.10):
the token checked before any of the file is read, the file streamed to a hidden .part and renamed only once whole;
each refusal (a stale token, a form out of order, no file, a name not a bundle's, one already there, too large, the disk
too full, a body cut short, no upload folder) says why with its status and keeps nothing. The real route through a
running site: tests/setup/site/upload_test.py.

    python3 tests/setup/site/save_upload_test.py
"""
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from fabriclib.setup.site.listener.multipart_reader import MultipartReader  # noqa: E402
from fabriclib.setup.site.listener.save_upload import UploadRefused, save_upload  # noqa: E402

FAILED = 0
B = "----fabricboundary"
NAME = "fabric-fabric-1-20261122T030000Z-uninstall.fabric.tar"
DATA = os.urandom(300_000) + b"\r\n--" + b"not the boundary" + os.urandom(5000)   # a near-boundary inside the file


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def body(parts):
    out = b""
    for name, filename, value in parts:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename is not None else "")
        out += f"--{B}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + value + b"\r\n"
    return out + f"--{B}--\r\n".encode()


def save(parts, cut=0, folder=None, **kw):
    kw.setdefault("free", lambda p: 1 << 40)
    folder = folder or tempfile.mkdtemp()
    raw = body(parts)
    raw = raw[:-cut] if cut else raw
    reader = MultipartReader(io.BytesIO(raw), len(raw), f"multipart/form-data; boundary={B}", size=4096)
    try:
        return save_upload(reader, "the-token", folder, **kw), None, folder
    except UploadRefused as exc:
        return None, exc, folder


GOOD = [("csrf", None, b"the-token"), ("seq", None, b"7"), ("bundle", NAME, DATA)]
out, err, folder = save(GOOD)
# covers: site:post.upload +
check("a whole upload: the question's number, the file under its own name, byte for byte, nothing else left",
      out == ("7", os.path.join(folder, NAME)) and open(out[1], "rb").read() == DATA
      and os.listdir(folder) == [NAME], (out, err, os.listdir(folder)))
ticks = []
save(GOOD, tick=lambda: ticks.append(1))
check("the person is heard as still here while it arrives", len(ticks) > 10, len(ticks))
out, err, folder = save([("csrf", None, b"the-token"), ("seq", None, b"7"), ("bundle", "C:\\Users\\x\\" + NAME, DATA)])
check("a browser that sends a full path: only the name is kept", out and os.path.basename(out[1]) == NAME, (out, err))

# covers: site:post.upload -
for name, parts, kw, status, words in (
        ("a stale token", [("csrf", None, b"old")] + GOOD[1:], {}, 403, "security token is stale"),
        ("the file before the token", [GOOD[2], GOOD[0], GOOD[1]], {}, 403, "security token is stale"),
        ("no question's number", [GOOD[0], GOOD[2]], {}, 400, "not this site's"),
        ("no file chosen", GOOD[:2] + [("bundle", None, b"")], {}, 400, "no file was chosen"),
        ("a name that is not a bundle's", GOOD[:2] + [("bundle", "photo.tar", DATA)], {}, 400, "not a bundle's"),
        ("larger than the limit", GOOD, {"limit": 100_000}, 413, "larger than"),
        ("the disk too full", GOOD, {"free": lambda p: 2 << 30, "reserve": 2 << 30}, 507, "GiB free")):
    out, err, folder = save(parts, **kw)
    check(f"negative: {name}: {status}, saying why, nothing kept", out is None and err and err.status == status
          and words in str(err) and os.listdir(folder) == [], (err and (err.status, str(err)), os.listdir(folder)))
out, err, folder = save(GOOD, cut=len(DATA) // 2)
check("negative: a body cut short: 400, the .part removed", err and err.status == 400 and "cut short" in str(err)
      and os.listdir(folder) == [], (err, os.listdir(folder)))
out, err, folder = save(GOOD, folder=os.path.join(tempfile.mkdtemp(), "gone"))
check("negative: no upload folder (the bundle is not being asked): 409", err and err.status == 409, err)
folder = tempfile.mkdtemp()
open(os.path.join(folder, NAME), "wb").close()
out, err, folder = save(GOOD, folder=folder)
check("negative: the same name already uploaded: 400, the first kept as it was",
      err and err.status == 400 and os.path.getsize(os.path.join(folder, NAME)) == 0, err)
try:
    MultipartReader(io.BytesIO(b"x=1"), 3, "application/x-www-form-urlencoded")
    check("negative: not a multipart form: refused", False)
except ValueError as exc:
    check("negative: not a multipart form: refused", "not a form with a file" in str(exc), exc)

print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
