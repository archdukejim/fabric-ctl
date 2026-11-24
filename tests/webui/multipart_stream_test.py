#!/usr/bin/env python3
"""The upload's multipart reader (webui/httpio/multipart_stream; manual 1.3.7.9): parts read in order with their data
exactly as sent, whatever piece size cuts the boundary (1 byte up), data holding boundary-like bytes kept, and a body cut
short or not multipart refused. Pure logic.

    python3 tests/webui/multipart_stream_test.py
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "src"))
from webui.agentclient.errors import ValidationError  # noqa: E402
from webui.httpio.multipart_stream import MultipartStream  # noqa: E402

FAILED = 0
B = "XyZ123boundary"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:300]}"))


def body(csrf, data, filename="fabric-h-20261123T010000Z-manual.fabric.tar"):
    return (f"preamble\r\n--{B}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{csrf}\r\n"
            f"--{B}\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"{filename}\"\r\n"
            "Content-Type: application/x-tar\r\n\r\n").encode() + data + f"\r\n--{B}--\r\n".encode()


def read_all(raw, size):
    mp = MultipartStream(io.BytesIO(raw), len(raw), f"multipart/form-data; boundary={B}", size=size)
    first = mp.next_part()
    csrf = mp.read_small()
    second = mp.next_part()
    data = b"".join(mp.read_part())
    return first, csrf, second, data, mp.next_part()


DATA = os.urandom(5000) + f"\r\n--{B[:-1]}".encode() + b"\r\n--" + os.urandom(3000)   # near-boundaries inside
bad = [size for size in (1, 2, 3, 7, 16, 17, 64, 1000, 1 << 20)
       if read_all(body("tok", DATA), size) != (("csrf", None), "tok", ("bundle",
                                                                        "fabric-h-20261123T010000Z-manual.fabric.tar"),
                                                DATA, None)]
check("every piece size from 1 byte up: the CSRF field, then the file's name and its bytes exactly, then the end",
      not bad, bad)
check("an empty file part reads as empty", read_all(body("tok", b""), 5)[3] == b"")
raw = body("tok", DATA)
for name, make in (("cut short", lambda: MultipartStream(io.BytesIO(raw[:-200]), len(raw) - 200,
                                                          f"multipart/form-data; boundary={B}", size=64)),):
    mp = make()
    try:
        mp.next_part()
        mp.read_small()
        mp.next_part()
        b"".join(mp.read_part())
        check(f"negative: a body {name} is refused", False)
    except ValidationError as exc:
        check(f"negative: a body {name} is refused", "cut short" in str(exc), exc)
try:
    MultipartStream(io.BytesIO(b"a=b"), 3, "application/x-www-form-urlencoded")
    check("negative: a form that is not multipart is refused", False)
except ValidationError as exc:
    check("negative: a form that is not multipart is refused", "not a form with a file" in str(exc), exc)
mp = MultipartStream(io.BytesIO(body("x" * 2000, b"")), 9999, f"multipart/form-data; boundary={B}")
mp.next_part()
try:
    mp.read_small()
    check("negative: a CSRF field past 1 KiB is refused", False)
except ValidationError as exc:
    check("negative: a CSRF field past 1 KiB is refused", "too long" in str(exc), exc)
print(f"\n{'all passed' if not FAILED else f'{FAILED} failed'}")
sys.exit(1 if FAILED else 0)
