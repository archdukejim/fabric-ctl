"""Setup's ready gate (decision 2.1.2.25): "fabric is ready" only once what a person reaches first answers, all at once.
Pure logic: the probes and the clock are stubbed (the host suite and the installer test meet the real ones).
    python3 tests/setup/wait_ready_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.setup.wait_ready as wr  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def after(n):
    """a probe that fails n times, then passes"""
    seen = [0]

    def probe():
        seen[0] += 1
        return seen[0] > n
    return probe


c = Clock()
got = wr.wait_ready([("landing", after(0)), ("database", after(3))], timeout=60, interval=5, clock=c.now,
                    sleep=c.sleep)
check("waits until every check passes in the same round (the database settles after 3 rounds)",
      got == [] and c.t == 15, (got, c.t))
c = Clock()
got = wr.wait_ready([("landing", after(0)), ("sign-in", after(99))], timeout=30, interval=5, clock=c.now,
                    sleep=c.sleep)
check("negative: a check still failing when the time is up is named, the others not", got == ["sign-in"], got)


class Ctx:
    vars = {"host_ip": "192.0.2.5", "ip_nginx": "10.255.0.10", "domain": "lan.test", "hostname_keycloak": "sso.lan.test",
            "hostname_mgr": "fabric.lan.test", "install_keycloak": True, "install_webui": True,
            "webui_client_cert": True}

    def path(self, *p):
        return "/opt/" + "/".join(p)


calls = []
wr._code = lambda url, name, ip, port, cafile: (calls.append((url, ip, port, cafile)) or
                                                {"http://192.0.2.5/info/": "200"}.get(url, "400" if "fabric." in url
                                                                                       else "200"))
wr._refusals = lambda since: 0
names = [n for n, _ in wr.probes(Ctx())]
check("the probes: the landing page by address, sign-in (the realm's discovery), Keycloak's database, the console",
      len(names) == 4 and "http://192.0.2.5/info/" in names[0] and "realms/lan.test" in names[1]
      and "Postgres" in names[2] and "fabric.lan.test" in names[3], names)
wr.TIMEOUT = 1
wr.run(Ctx())
check("…sign-in and the console checked against fabric's root, at nginx's address; the console wants 400 (a client "
      "certificate asked)", any("openid-configuration" in u and ip == "10.255.0.10" and ca.endswith("root_ca.crt")
                                for u, ip, _, ca in calls if ca), calls)
wr._refusals = lambda since: 2
try:
    wr.run(Ctx())
    check("negative: refusals in Postgres's log keep setup from saying it is ready", False)
except SetupError as e:
    check("negative: refusals in Postgres's log keep setup from saying it is ready, naming the check and doctor",
          "Keycloak's database" in str(e) and "fabricctl doctor" in str(e), e)

# an install ready for the first time records it (2.1.4.10): from then on the landing page's alias is the admin's
import tempfile  # noqa: E402
import yaml  # noqa: E402


class FirstCtx(Ctx):
    def __init__(self, folder, was_ready):
        self.config_dir, self.vars_file = folder, os.path.join(folder, "vars.yaml")
        self.vars = {**Ctx.vars, "install_was_ready": was_ready}
        with open(self.vars_file, "w") as f:
            yaml.safe_dump({"domain": "lan.test", "install_was_ready": was_ready}, f)


def stored(ctx):
    with open(ctx.vars_file) as f:
        return yaml.safe_load(f)


wr._refusals = lambda since: 0
with tempfile.TemporaryDirectory() as d:
    ctx = FirstCtx(d, False)
    wr.run(ctx)
    check("a first install once ready records install_was_ready: true in its settings, the rest kept",
          stored(ctx) == {"domain": "lan.test", "install_was_ready": True} and ctx.vars["install_was_ready"], stored(ctx))
with tempfile.TemporaryDirectory() as d:
    ctx = FirstCtx(d, False)
    wr._refusals = lambda since: 2
    try:
        wr.run(ctx)
    except SetupError:
        pass
    check("negative: an install not ready records nothing (its next run adds the alias again)",
          stored(ctx)["install_was_ready"] is False, stored(ctx))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
