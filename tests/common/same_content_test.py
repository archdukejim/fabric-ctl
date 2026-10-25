"""Two files compared byte for byte on every call (`common/same_content`, 2.3.1.29): `filecmp.cmp` cached its answer by
each file's (type, size, mtime) even with shallow=False, so a same-size rewrite within one mtime tick read as the
same. Real files in a temporary folder; the mtime is set back by hand to make the tick deterministic.
    python3 tests/common/same_content_test.py"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.same_content import same_content  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


with tempfile.TemporaryDirectory() as t:
    a, b = os.path.join(t, "a"), os.path.join(t, "b")
    write(a, b"x = 1\n")
    write(b, b"x = 1\n")
    check("positive: the same bytes are the same", same_content(a, b))
    st = os.stat(b)
    check("positive: asked again, still the same (nothing cached wrongly either way)", same_content(a, b))
    write(b, b"x = 2\n")
    os.utime(b, ns=(st.st_atime_ns, st.st_mtime_ns))
    check("negative: a same-size rewrite with the mtime unchanged is different", not same_content(a, b))
    write(b, b"x = 1\n")
    os.utime(b, ns=(st.st_atime_ns + 5 * 10**9, st.st_mtime_ns + 5 * 10**9))
    check("positive: only the mtime moved: the same", same_content(a, b))
    write(b, b"x = 10\n")
    check("negative: a different size is different", not same_content(a, b))
    big = os.urandom(200000)
    write(a, big)
    write(b, big[:-1] + bytes([big[-1] ^ 1]))
    check("negative: files past one read block that differ only in their last byte are different",
          not same_content(a, b))
    write(b, big)
    check("positive: files past one read block with the same bytes are the same", same_content(a, b))
    write(a, b"")
    write(b, b"")
    check("positive: two empty files are the same", same_content(a, b))
    try:
        same_content(a, os.path.join(t, "missing"))
        raised = False
    except OSError:
        raised = True
    check("negative: a missing file raises OSError", raised)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
