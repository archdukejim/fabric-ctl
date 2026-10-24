"""A container unit's start waits until its old container is really gone (manual 1.2.4.4): the shared unit template
(templates/systemd/wrapper.service.j2) rendered, and its wait run with bash against a stand-in `docker` that answers
the old container present for a while (an overlapping start's removal still under way) and a stand-in `sleep`.
Pure: nothing of Docker's or systemd's is touched (the sandbox and the lab run the real units).
    python3 tests/deploy/unit_start_wait_test.py"""
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.jinja_env import jinja_env  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def unit(service, **v):
    """The rendered unit of one service, its continued lines joined."""
    item = {"service": service, "folder": service, "compose": service}
    text = jinja_env(os.path.join(REPO, "templates")).get_template("systemd/wrapper.service.j2").render(
        **{"deploy_base_dir": "/opt", "host_ram_capacity": 8, **v}, item=item)
    return text.replace("\\\n", "")


def lines(text, key):
    return [ln[len(key) + 1:] for ln in text.splitlines() if ln.startswith(key + "=")]


WORK = tempfile.mkdtemp(prefix="fabric-unit-wait-")


def run_wait(script, present_for):
    """The wait's script with `docker container inspect` answering "present" present_for times, then "gone".
    Returns (exit code, output, the sleeps taken, the inspects asked)."""
    bin_dir = os.path.join(WORK, "bin")
    shutil.rmtree(bin_dir, ignore_errors=True)
    os.makedirs(bin_dir)
    log = os.path.join(WORK, "calls")
    open(log, "w").close()
    fakes = {
        "docker": f'echo "docker $*" >> {shlex.quote(log)}\n'
                  f'n=$(grep -c "^docker container inspect" {shlex.quote(log)})\n'
                  f'[ "$n" -le {present_for} ]\n',
        "sleep": f'echo "sleep $*" >> {shlex.quote(log)}\n',
    }
    for name, body in fakes.items():
        path = os.path.join(bin_dir, name)
        with open(path, "w") as f:
            f.write("#!/bin/bash\n" + body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    argv = shlex.split(script)
    res = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                         env={"PATH": bin_dir + ":/usr/bin:/bin"})
    calls = open(log).read().splitlines()
    return (res.returncode, res.stdout + res.stderr, [c for c in calls if c.startswith("sleep")],
            [c for c in calls if c.startswith("docker container inspect")])


try:
    kc = unit("keycloak")
    pre = lines(kc, "ExecStartPre")
    waits = [p for p in pre if "container inspect" in p]
    check("the unit waits for the old container after removing it, before it starts the new one",
          len(waits) == 1 and pre.index(waits[0]) == len(pre) - 1 and "rm -fsv" in pre[-2]
          and kc.index(waits[0]) < kc.index("ExecStart=/usr/bin/docker compose"), pre)
    check("…the wait is not ignorable (no leading '-'): a container that stays fails the start",
          waits and waits[0].startswith("/bin/bash -c "), waits)
    small = unit("postgres", host_ram_capacity=4)
    check("every container unit shares it, the small host's staggered starts too",
          all(len([p for p in lines(unit(s), "ExecStartPre") if "container inspect" in p]) == 1
              for s in ("postgres", "nginx", "bind9", "samba", "openbao"))
          and [p for p in lines(small, "ExecStartPre") if "container inspect" in p], small[:200])

    code, out, sleeps, asked = run_wait(waits[0], 0)
    check("positive: the old container already gone: the start goes on at once", code == 0 and sleeps == [], (code, out))
    code, out, sleeps, asked = run_wait(waits[0], 3)
    check("positive: a removal still under way (3 s): waited out, then the start goes on",
          code == 0 and len(sleeps) == 3 and asked[-1].endswith("inspect keycloak"), (code, out, sleeps))
    code, out, sleeps, asked = run_wait(waits[0], 1000)
    check("negative: still there after 60 s: the start fails, saying so (bounded: 60 looks)",
          code == 1 and len(sleeps) == 60 and "Container keycloak still there 60 s after its removal" in out,
          (code, out, len(sleeps)))
finally:
    shutil.rmtree(WORK, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
