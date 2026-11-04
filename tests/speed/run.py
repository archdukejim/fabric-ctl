#!/usr/bin/env python3
"""What a process keeps between requests (manual 1.8.8.2, decision 2.1.8.35), with no container: load_vars, load_secrets
through held_read, and cert_dates. Kept is only ever fast: each is read again when its source changes.

    python3 tests/speed/run.py
"""
import datetime
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))

import fabriclib.common.load_vars as m_vars  # noqa: E402
import fabriclib.deploy.running_build as m_build  # noqa: E402
from fabriclib.common.load_vars import load_vars  # noqa: E402
from fabriclib.pki.common import cert_dates as m_dates  # noqa: E402
from fabriclib.secrets import held_secrets as m_held  # noqa: E402

FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"  -> {detail}" if not cond else ""))
    FAILED += 0 if cond else 1


with tempfile.TemporaryDirectory() as tmp:
    # ---- which build the host's services run (2.1.1.83)
    m_build.version_info = lambda: {"version": "1.0", "build": "a"}
    check("no build recorded yet: the services are restarted", m_build.build_changed(tmp))
    m_build.record_build(tmp)
    check("the same build: left alone", not m_build.build_changed(tmp))
    m_build.version_info = lambda: {"version": "1.0", "build": "b"}
    check("a package update: the services are restarted", m_build.build_changed(tmp))

    # ---- the settings
    path = os.path.join(tmp, "vars.yaml")
    check("negative: no file, no settings", load_vars(path) == {})
    with open(path, "w") as f:
        f.write("a: 1\nb: [x]\n")
    first = load_vars(path)
    check("the file's settings", first == {"a": 1, "b": ["x"]}, first)
    first["b"].append("changed by the caller")
    check("what one caller does to its settings the next does not see", load_vars(path) == {"a": 1, "b": ["x"]})
    with open(path, "w") as f:
        f.write("a: 2\nb: [x]\n")
    check("the file changed in place: read again", load_vars(path)["a"] == 2)
    with open(path + ".new", "w") as f:
        f.write("a: 3\nb: [x]\n")
    stat = os.stat(path)
    os.utime(path + ".new", ns=(stat.st_atime_ns, stat.st_mtime_ns))
    os.replace(path + ".new", path)
    check("the file replaced, same time and size: its inode tells, read again", load_vars(path)["a"] == 3)
    os.utime(path, (1, 1))
    load_vars(path)
    real_load, asked = m_vars.yaml.safe_load, []
    m_vars.yaml.safe_load = lambda s: asked.append(1) or real_load(s)
    kept = load_vars(path)
    check("settled and unchanged: kept, not parsed again", kept["a"] == 3 and asked == [], asked)
    m_vars.yaml.safe_load = real_load
    with open(path, "w") as f:
        f.write("a: [\n")
    try:
        load_vars(path)
        bad = False
    except Exception as e:      # noqa: BLE001
        bad = type(e).__name__.endswith("Error")
    check("negative: a broken file is an error, not the settings it held before", bad)

    # ---- the secrets
    reads = []

    def read():
        reads.append(1)
        return {"s": ["v"], "n": len(reads)}

    m_held.held_read(read)
    m_held.held_read(read)
    check("a process that does not hold them (a command) reads each time", len(reads) == 2, reads)
    reads.clear()
    m_held.hold_secrets()
    one = m_held.held_read(read)
    one["s"].append("changed by the caller")
    two = m_held.held_read(read)
    check("fabric-agent: read once within the time, each caller its own copy", len(reads) == 1 and two["s"] == ["v"], two)
    m_held.forget_secrets()
    check("fabric-agent: what it wrote itself is read again", m_held.held_read(read)["n"] == 2)
    m_held._at -= m_held.HOLD_SECONDS + 1
    check("fabric-agent: past the time, read again", m_held.held_read(read)["n"] == 3)
    m_held.forget_secrets()

    def sealed():
        raise ValueError("OpenBao is sealed")

    try:
        m_held.held_read(sealed)
        said = ""
    except ValueError as e:
        said = str(e)
    check("negative: a read that fails says so and nothing is kept", said == "OpenBao is sealed" and m_held._value is None)
    write = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "fabriclib", "secrets",
                              "common", "write_vault_secrets.py")).read()
    check("writing the secrets forgets what is kept", "forget_secrets()" in write)

    # ---- a certificate's dates
    def cert(name, days):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-keyout", os.path.join(tmp, "key.pem"), "-out", name, "-days", str(days), "-subj", "/CN=x"],
                       check=True, capture_output=True)

    pem = os.path.join(tmp, "c.pem")
    cert(pem, 10)
    now = datetime.datetime.now(datetime.timezone.utc)
    left = (m_dates.cert_dates(pem)[1] - now).days
    check("a certificate's dates", 9 <= left <= 10, left)
    asked = []
    real = m_dates._read_dates
    m_dates._read_dates = lambda p: asked.append(p) or real(p)
    m_dates.cert_dates(pem)
    check("asked again, unchanged: openssl is not run", asked == [], asked)
    cert(pem, 100)
    left = (m_dates.cert_dates(pem)[1] - now).days
    check("renewed in place: its new dates", asked == [pem] and 99 <= left <= 100, (asked, left))
    with open(os.path.join(tmp, "not.pem"), "w") as f:
        f.write("not a certificate")
    check("negative: a file that is not a certificate gives no dates", m_dates.cert_dates(os.path.join(tmp, "not.pem"))
          is None)
    check("negative: a missing file gives no dates", m_dates.cert_dates(os.path.join(tmp, "gone.pem")) is None)

print(f"\n{FAILED and 'FAILED' or 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
