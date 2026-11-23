#!/usr/bin/env python3
"""A bundle's upload in fabric-agent (agent/post_upload, agent/read_chunked, backup/receive_upload; manual 1.3.7.9):
chunked or of a known length, written to a hidden .part file and renamed only once checked whole; refused, with no file
left, for someone who is not a Domain Admin (before a byte is read), a name that is not a bundle's or already there, a
body too large or cut short, a disk too full, a file that is not whole. Real files in a temporary folder; the bundle's
check stood in for (a real bundle's: tests/sandbox/run.sh).

    python3 tests/agent/post_upload_test.py
"""
import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
import agent.post_upload as pu  # noqa: E402
from agent.read_chunked import read_chunked  # noqa: E402
from fabriclib.backup.receive_upload import receive_upload  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

FAILED = 0
NAME = "fabric-fabric-20261123T010000Z-manual.fabric.tar"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def chunked(data, size=7):
    out = b"".join(f"{len(data[i:i + size]):x}\r\n".encode() + data[i:i + size] + b"\r\n"
                   for i in range(0, len(data), size))
    return out + b"0\r\n\r\n"


def whole(path):
    if not open(path, "rb").read().startswith(b"manifest.json"):
        raise ValidationError("not a bundle: no manifest.json")
    return {}


DATA = b"manifest.json" + os.urandom(20000)
check("chunked: the body read back exactly, in pieces of at most the size asked",
      b"".join(read_chunked(io.BytesIO(chunked(DATA)), size=5)) == DATA)
try:
    b"".join(read_chunked(io.BytesIO(chunked(DATA)[:-40])))
    check("negative: a chunked body cut short is refused", False)
except ValidationError as exc:
    check("negative: a chunked body cut short is refused", "cut short" in str(exc), exc)


def upload(name, data, user="dana", admin=True, folder=None, chunk=True, **kw):
    folder = folder or tempfile.mkdtemp()
    audits = []
    headers = {"X-Fabric-Bundle": name, **({"Transfer-Encoding": "chunked"} if chunk
                                            else {"Content-Length": str(len(data))})}
    body = io.BytesIO(chunked(data) if chunk else data)
    try:
        out = pu.post_upload(user, headers, body, load=lambda: {}, allowed=lambda v, c: admin,
                             receive=lambda n, p: receive_upload(n, p, folder=folder, check=whole, **kw),
                             audit=lambda *a, **k: audits.append(a))
        return out, None, folder, audits, body.tell()
    except ValidationError as exc:
        return None, str(exc), folder, audits, body.tell()


out, err, folder, audits, _ = upload(NAME, DATA)
path = os.path.join(folder, NAME)
check("a chunked upload: the bundle in the folder under its name, 0600, its bytes exact, audited, no .part left",
      out == {"file": NAME, "size": len(DATA)} and open(path, "rb").read() == DATA
      and (os.name == "nt" or oct(os.stat(path).st_mode & 0o777) == "0o600") and audits[0][1] == "BACKUP_UPLOAD"
      and os.listdir(folder) == [NAME], (out, err, os.listdir(folder)))
out, err, folder, _, _ = upload(NAME, DATA, chunk=False)
check("an upload of a known length: the same", out and open(os.path.join(folder, NAME), "rb").read() == DATA, err)
out, err, folder, audits, read = upload(NAME, DATA, admin=False)
check("negative: not a Domain Admin: refused before a byte is read, nothing written or audited",
      "Domain Admins" in (err or "") and read == 0 and not os.listdir(folder) and not audits, (err, read))
for name, args, words in (("a name that is not a bundle's", ("holiday.tar", DATA), "not a bundle's"),
                          ("a path for a name", ("../" + NAME, DATA), "not a bundle's"),
                          ("not a bundle inside", (NAME, b"PK\3\4" + DATA), "no manifest.json")):
    out, err, folder, audits, _ = upload(*args)
    check(f"negative: {name}: refused, no file left, not audited", words in (err or "") and not os.listdir(folder)
          and not audits, (err, os.listdir(folder)))
out, err, folder, _, _ = upload(NAME, DATA, limit=1000)
check("negative: past the size limit: refused, no file left", "larger than" in (err or "")
      and not os.listdir(folder), err)
out, err, folder, _, _ = upload(NAME, DATA, free=lambda p: 2 << 30, reserve=(2 << 30) - 3)
check("negative: the disk would be too full: refused, no file left", "less than" in (err or "")
      and not os.listdir(folder), err)
folder = tempfile.mkdtemp()
open(os.path.join(folder, NAME), "wb").write(b"kept")
out, err, folder, _, _ = upload(NAME, DATA, folder=folder)
check("negative: a bundle of that name is there already: refused, it is kept as it was",
      "already" in (err or "") and open(os.path.join(folder, NAME), "rb").read() == b"kept"
      and os.listdir(folder) == [NAME], err)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
