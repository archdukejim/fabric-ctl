"""Per-run names for the container suites (manual 3.1.2.6): two runs from different worktrees never take each other's
containers, networks, subnets or images, and a run removes only what it made.

- The run's id is a short hash of the worktree's path (FABRIC_TEST_RUN overrides it: 1 to 12 of a-z, 0-9), so nothing
  needs setting. Names are `<base>-<id>`; every container and network a suite makes carries the label
  `fabric.test.run=<id>`, and is removed only when it carries it.
- Subnets: each run takes its own second octet, `10.<n>`, n from 100 to 199 by the same hash
  (FABRIC_TEST_NET_PREFIX overrides it: `10.<n>`); a suite keeps its own third octet. A network that overlaps one
  this run did not make is refused, saying which, never removed.
- Suites that start fabric's own containers, whose names the product fixes (`bind9`, `postgres`, `openbao`, ...),
  cannot take per-run names: they hold one machine-wide lock instead (`product_names_lock`), so a second run waits.

Used as a module by the Python suites, and from bash:
    python3 tests/common/test_run.py name BASE | id | label | prefix | port BASE
    python3 tests/common/test_run.py remove container|network NAME...
    python3 tests/common/test_run.py network NAME CIDR [GATEWAY]
    python3 tests/common/test_run.py compose FILE SERVICE...    (prints the override that labels them)"""
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time

REPO = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
LOCK = "/tmp/fabric-tests-product-names.lock"     # beside the sandbox's own (/tmp/fabric-sandbox-suite.lock)


class Refused(RuntimeError):
    """A name, label or subnet this run may not take or remove; the message says which and what to do."""


def _digest(repo):
    return hashlib.sha256(repo.encode()).hexdigest()


def run_id(env=None, repo=REPO):
    """Purpose: this run's id: FABRIC_TEST_RUN, else the first 6 hex digits of a hash of the worktree's path.
    Inputs:  env — the environment (default os.environ); repo — the worktree's path.
    Returns: str.
    Fails:   Refused for a FABRIC_TEST_RUN that is not 1 to 12 of a-z, 0-9."""
    env = os.environ if env is None else env
    given = env.get("FABRIC_TEST_RUN", "")
    if given:
        if not re.fullmatch(r"[a-z0-9]{1,12}", given):
            raise Refused(f"FABRIC_TEST_RUN={given!r}: use 1 to 12 of a-z and 0-9")
        return given
    return _digest(repo)[:6]


def net_prefix(env=None, repo=REPO):
    """Purpose: this run's first two octets: FABRIC_TEST_NET_PREFIX, else `10.<n>` with n from 100 to 199 by the
             worktree's hash.
    Inputs:  env, repo — as run_id.
    Returns: str, e.g. "10.142".
    Fails:   Refused for a FABRIC_TEST_NET_PREFIX that is not `10.<1-254>`."""
    env = os.environ if env is None else env
    given = env.get("FABRIC_TEST_NET_PREFIX", "")
    if given:
        m = re.fullmatch(r"10\.(\d{1,3})", given)
        if not m or not 1 <= int(m.group(1)) <= 254:
            raise Refused(f"FABRIC_TEST_NET_PREFIX={given!r}: use 10.<n>, n from 1 to 254")
        return given
    return f"10.{100 + int(_digest(repo), 16) % 100}"


RUN = run_id()
PREFIX = net_prefix()
LABEL = f"fabric.test.run={RUN}"


def name(base, run=None):
    """Purpose: a container's, network's or image tag's name for this run: `<base>-<id>`.
    Inputs:  base — str; run — the id (default this run's).
    Returns: str."""
    return f"{base}-{run or RUN}"


def net(octet, prefix=None):
    """Purpose: a suite's /24 for this run, as its first three octets: `<prefix>.<octet>`.
    Inputs:  octet — the suite's own third octet (int, 0 to 255); prefix — default this run's.
    Returns: str, e.g. "10.142.9" (the suite writes f"{NET}.0/24", f"{NET}.10").
    Fails:   Refused for an octet outside 0 to 255."""
    if not (isinstance(octet, int) and 0 <= octet <= 255):
        raise Refused(f"third octet {octet!r}: use 0 to 255")
    return f"{prefix or PREFIX}.{octet}"


def port(base, prefix=None):
    """Purpose: a host port for this run, for a suite's stand-in server on the host: base plus the prefix's second
             octet modulo 100, so two runs' prefixes give two ports.
    Inputs:  base — the suite's own port (int, 1024 to 65435); prefix — default this run's.
    Returns: int.
    Fails:   Refused for a base outside 1024 to 65435."""
    if not (isinstance(base, int) and 1024 <= base <= 65435):
        raise Refused(f"base port {base!r}: use 1024 to 65435")
    return base + int((prefix or PREFIX).split(".")[1]) % 100


def labels():
    """Purpose: the arguments that label what `docker run` or `docker network create` makes as this run's."""
    return ["--label", LABEL]


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True)


def owner(kind, ref):
    """Purpose: who made a container or network: this run's label, another's, or none.
    Inputs:  kind — "container" or "network"; ref — its name.
    Returns: None when there is none by that name; else the value of its fabric.test.run label ("" when it has
             none: not a test's, or made before 2026-10-25).
    Fails:   Refused for another kind."""
    if kind not in ("container", "network"):
        raise Refused(f"kind {kind!r}: container or network")
    res = _docker(kind, "inspect", "-f", '{{index .Config.Labels "fabric.test.run"}}' if kind == "container"
                  else '{{index .Labels "fabric.test.run"}}', ref)
    if res.returncode:
        return None
    out = res.stdout.strip()
    return "" if out == "<no value>" else out


def remove(kind, *names, run=None):
    """Purpose: remove this run's containers or networks by name; never one this run did not make.
    Inputs:  kind — "container" or "network"; names — str; run — the id (default this run's).
    Returns: list of the names removed (one that is not there is skipped).
    Fails:   Refused for a name held by something else (another run's, or not a test's), naming it; the names before
             it are removed, the rest left."""
    run, done = run or RUN, []
    for n in names:
        who = owner(kind, n)
        if who is None:
            continue
        if who != run:
            raise Refused(f"{kind} {n} is not this run's ({run}): "
                          + (f"run {who}'s" if who else "it has no fabric.test.run label (not a test's, or older)")
                          + "; left as it is: remove it yourself if it is stale")
        _docker("rm", "-f", n) if kind == "container" else _docker("network", "rm", n)
        done.append(n)
    return done


def _networks():
    """Purpose: every Docker network's name, run label and IPv4 subnets."""
    ids = _docker("network", "ls", "-q").stdout.split()
    if not ids:
        return []
    out = _docker("network", "inspect", *ids)
    found = []
    for n in json.loads(out.stdout or "[]"):
        subnets = [c.get("Subnet") for c in (n.get("IPAM") or {}).get("Config") or [] if c.get("Subnet")]
        found.append((n["Name"], (n.get("Labels") or {}).get("fabric.test.run", ""), subnets))
    return found


def overlaps(cidr, networks):
    """Purpose: the networks whose IPv4 subnets overlap cidr.
    Inputs:  cidr — str; networks — [(name, run label, [subnet, ...])] as _networks gives.
    Returns: list of (name, run label, subnet).
    Fails:   ValueError for a cidr that is not one."""
    want = ipaddress.ip_network(cidr)
    hits = []
    for nname, who, subnets in networks:
        for s in subnets:
            try:
                theirs = ipaddress.ip_network(s)
            except ValueError:
                continue
            if theirs.version == want.version and theirs.overlaps(want):
                hits.append((nname, who, s))
    return hits


def create_network(nname, cidr, gateway=None, run=None):
    """Purpose: make this run's network on its subnet: one of this run's by that name is removed first; one that
             overlaps and is not this run's is refused, never touched.
    Inputs:  nname — the network's name; cidr — its subnet; gateway — optional; run — default this run's.
    Returns: None.
    Fails:   Refused naming the overlapping network (and FABRIC_TEST_NET_PREFIX to pick another range); RuntimeError
             when docker refuses."""
    run = run or RUN
    remove("network", nname, run=run)
    clash = [h for h in overlaps(cidr, _networks()) if h[0] != nname]
    if clash:
        n, who, s = clash[0]
        raise Refused(f"subnet {cidr} overlaps network {n} ({s}, "
                      + (f"run {who}'s" if who else "not a test's") + "): left as it is; "
                      + "set FABRIC_TEST_NET_PREFIX=10.<n> for another range")
    res = _docker("network", "create", "--label", f"fabric.test.run={run}", "--subnet", cidr,
                  *(["--gateway", gateway] if gateway else []), nname)
    if res.returncode:
        raise RuntimeError(f"docker network create {nname}: {res.stderr.strip()[-400:]}")


def compose_files(compose_file, *services, run=None):
    """Purpose: label the containers a fabric compose file starts as this run's, without changing that file: an
             override beside it gives each named service the run's label.
    Inputs:  compose_file — the rendered docker-compose.yml; services — its service names; run — default this run's.
    Returns: the `-f` arguments for `docker compose`: [-f, compose_file, -f, override]."""
    override = os.path.join(os.path.dirname(compose_file), "test-run.override.yml")
    with open(override, "w") as f:
        f.write("services:\n" + "".join(f"  {s}:\n    labels:\n      fabric.test.run: \"{run or RUN}\"\n"
                                        for s in services))
    return ["-f", compose_file, "-f", override]


class product_names_lock:
    """Hold the machine-wide lock of the suites that start fabric's own containers under the product's fixed names
    (`bind9`, `postgres`, `openbao`, ...): a second run waits (up to `wait` seconds, saying for whom), then refuses.
    Used as `with product_names_lock("hardening"):`; from bash, `flock` on LOCK (tests/hardening/run.sh)."""

    def __init__(self, suite, wait=7200, path=LOCK):
        self.suite, self.wait, self.path, self.f = suite, wait, path, None

    def __enter__(self):
        self.f = open(self.path, "a+")
        deadline, told = time.monotonic() + self.wait, False
        while True:
            try:
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not told:
                    self.f.seek(0)
                    print(f"    waiting: another run holds fabric's container names ({self.f.read().strip()})",
                          flush=True)
                    told = True
                if time.monotonic() > deadline:
                    raise Refused(f"{self.suite}: another run held fabric's container names for {self.wait} s")
                time.sleep(5)
        self.f.seek(0)
        self.f.truncate()
        self.f.write(f"{self.suite} of run {RUN} ({REPO}), pid {os.getpid()}\n")
        self.f.flush()
        return self

    def __exit__(self, *exc):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()
        return False


if __name__ == "__main__":
    a = sys.argv[1:]
    try:
        if a[:1] == ["id"]:
            print(RUN)
        elif a[:1] == ["label"]:
            print(LABEL)
        elif a[:1] == ["prefix"]:
            print(PREFIX)
        elif a[:1] == ["port"] and len(a) == 2 and a[1].isdigit():
            print(port(int(a[1])))
        elif a[:1] == ["compose"] and len(a) >= 3:
            print(compose_files(a[1], *a[2:])[3])
        elif a[:1] == ["name"] and len(a) == 2:
            print(name(a[1]))
        elif a[:1] == ["remove"] and len(a) >= 3:
            remove(a[1], *a[2:])
        elif a[:1] == ["network"] and len(a) in (3, 4):
            create_network(a[1], a[2], *(a[3:]))
        else:
            print(__doc__.split("Used as a module", 1)[1].strip(), file=sys.stderr)
            sys.exit(2)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        sys.exit(3)
