"""The container suites' per-run names (`tests/common/test_run.py`, manual 3.1.2.6): ids, names and subnets per
worktree; a run removes only what carries its label, and refuses a network that overlaps another's. The pure part runs
anywhere; with Docker reachable, a network and a created (never started) container of this test's own are made under
names of its own and removed after.
    sudo python3 tests/common/test_run_test.py"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_run as tr  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(fn):
    try:
        fn()
        return ""
    except tr.Refused as e:
        return str(e) or "refused"


a, b = tr.run_id({}, "/work/fabric-ctl-080"), tr.run_id({}, "/work/fabric-ctl-090")
check("positive: the id is derived from the worktree, the same each time, and differs between worktrees",
      a == tr.run_id({}, "/work/fabric-ctl-080") and a != b and len(a) == 6, (a, b))
check("positive: FABRIC_TEST_RUN overrides it", tr.run_id({"FABRIC_TEST_RUN": "ci7"}, "/x") == "ci7")
why = refused(lambda: tr.run_id({"FABRIC_TEST_RUN": "a b;rm"}, "/x"))
check("negative: a FABRIC_TEST_RUN that is not a-z, 0-9 is refused, saying so", "1 to 12 of a-z" in why, why)
p = tr.net_prefix({}, "/work/fabric-ctl-080")
check("positive: the subnet range is 10.<100-199> by the worktree, overridable",
      p.startswith("10.") and 100 <= int(p.split(".")[1]) <= 199
      and tr.net_prefix({"FABRIC_TEST_NET_PREFIX": "10.42"}, "/x") == "10.42", p)
for bad in ("10.0", "10.255", "192.168", "10.1.2"):
    why = refused(lambda: tr.net_prefix({"FABRIC_TEST_NET_PREFIX": bad}, "/x"))
    check(f"negative: FABRIC_TEST_NET_PREFIX={bad} refused", "use 10.<n>" in why, why)
check("positive: a name and a /24 for this run", tr.name("kc-dc", "ab12cd") == "kc-dc-ab12cd"
      and tr.net(9, "10.142") == "10.142.9")
check("negative: a third octet outside 0 to 255 is refused", "use 0 to 255" in refused(lambda: tr.net(256, "10.1")))
check("positive: a host port per run: two prefixes, two ports", tr.port(18443, "10.142") == 18485
      and tr.port(18443, "10.143") == 18486)
check("negative: a base port outside 1024 to 65435 is refused", "use 1024 to 65435" in refused(lambda: tr.port(80, "10.1")))
_cdir = tempfile.mkdtemp()
_args = tr.compose_files(os.path.join(_cdir, "docker-compose.yml"), "openbao", run="ab12cd")
check("positive: a compose override labels each named service as this run's, beside the file",
      _args == ["-f", os.path.join(_cdir, "docker-compose.yml"), "-f", os.path.join(_cdir, "test-run.override.yml")]
      and open(_args[3]).read() == 'services:\n  openbao:\n    labels:\n      fabric.test.run: "ab12cd"\n')
shutil.rmtree(_cdir)
nets = [("other", "x1", ["10.142.9.0/24"]), ("mine", "ab12cd", ["10.142.10.0/24"]), ("host", "", [])]
check("positive: overlaps found by subnet, whoever made the network",
      tr.overlaps("10.142.9.128/25", nets) == [("other", "x1", "10.142.9.0/24")]
      and tr.overlaps("10.142.11.0/24", nets) == [])

docker = shutil.which("docker") and subprocess.run(["docker", "info"], capture_output=True).returncode == 0
if not docker:
    print("    (no Docker here: the label and network checks did not run)")
else:
    me, other = tr.name("trtest"), tr.name("trtest-other", "zz9999")
    plain = tr.name("trtest-plain")
    sub, sub2 = tr.net(250) + ".0/24", tr.net(251) + ".0/24"
    for c in (me, plain, other):
        subprocess.run(["docker", "rm", "-f", c], capture_output=True)      # this test's own names only
    for n in (me, other):
        subprocess.run(["docker", "network", "rm", n], capture_output=True)
    try:
        tr.create_network(me, sub)
        check("positive: this run's network made, labelled as this run's", tr.owner("network", me) == tr.RUN)
        tr.create_network(me, sub)
        check("positive: made again: this run's old one replaced", tr.owner("network", me) == tr.RUN)
        tr.create_network(other, sub2, run="zz9999")
        why = refused(lambda: tr.create_network(tr.name("trtest-clash"), sub2))
        check("negative: a subnet overlapping another run's network is refused, naming it; that network kept",
              other in why and "FABRIC_TEST_NET_PREFIX" in why and tr.owner("network", other) == "zz9999", why)
        img = "debian:trixie"
        subprocess.run(["docker", "create", "--name", me, *tr.labels(), img, "true"], capture_output=True)
        subprocess.run(["docker", "create", "--name", plain, img, "true"], capture_output=True)
        subprocess.run(["docker", "create", "--name", other, "--label", "fabric.test.run=zz9999", img, "true"],
                       capture_output=True)
        check("positive: this run's container is removed by name", tr.remove("container", me) == [me]
              and tr.owner("container", me) is None)
        why = refused(lambda: tr.remove("container", plain))
        check("negative: a container with no run label is refused, never removed",
              "no fabric.test.run label" in why and tr.owner("container", plain) == "", why)
        why = refused(lambda: tr.remove("container", other))
        check("negative: another run's container is refused, never removed",
              "run zz9999's" in why and tr.owner("container", other) == "zz9999", why)
        check("positive: a name that is not there is skipped", tr.remove("container", tr.name("trtest-none")) == [])
        out = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_run.py"),
                              "remove", "container", plain], capture_output=True, text=True)
        check("negative: from bash too: refused, exit 3, saying why", out.returncode == 3 and "refused:" in out.stderr,
              (out.returncode, out.stderr))
    finally:
        for c in (me, plain, other):
            subprocess.run(["docker", "rm", "-f", c], capture_output=True)
        for n in (me, other):
            subprocess.run(["docker", "network", "rm", n], capture_output=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
