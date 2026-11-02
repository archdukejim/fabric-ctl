"""run_dc (tests/samba/start_dc.py) and Samba's RPC port race at start (manual 2.3.6.26): a test DC that exits only
because an RPC endpoint's port was taken is started again, at most twice, as fabric's unit restarts it; a DC that
exits for any other reason, or keeps losing, still fails. Pure: docker stood in for.
    python3 tests/samba/start_dc_test.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import start_dc as sd  # noqa: E402

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS, FAIL = PASS + bool(ok), FAIL + (not ok)
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


class Env:
    """Renders the one compose file run_dc reads."""
    def get_template(self, name):
        class T:
            def render(self, **v):
                return ("services:\n  samba:\n    mem_limit: 512m\n    cap_add: []\n    security_opt: []\n"
                        "    tmpfs: []\n    environment: {}\n    volumes: []\n"
                        "    healthcheck: {test: [CMD, samba-tool, domain, info, 127.0.0.1]}\n")
        return T()


class Docker:
    """docker inspect/logs/run/start as a scripted container: each start goes through `states`, its log `log`."""
    def __init__(self, runs):
        self.runs, self.run_no, self.step, self.calls = runs, 0, 0, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd[:2])
        out = ""
        if cmd[1] in ("run", "start"):
            self.run_no += 1 if cmd[1] == "start" else 0
            self.step = 0
        elif cmd[1] == "inspect":
            states = self.runs[min(self.run_no, len(self.runs) - 1)][0]
            out = states[min(self.step, len(states) - 1)]
            self.step += 1
        elif cmd[1] == "logs":
            out = "".join(r[1] for r in self.runs[:self.run_no + 1])
        return sd.subprocess.CompletedProcess(cmd, 0, out, "")


RACE = ("service_setup_stream_socket(address=10.9.9.30,port=49154) for samr wkssvc mgmt failed - "
        f"{sd.RPC_PORT_RACE}\n")
V = {"hostname": "dc9", "host_ip": "10.9.9.30"}
sd.testrun.remove = lambda *a: None
sd.time.sleep = lambda s: None


def run(runs, tries=10):
    d = Docker(runs)
    sd.subprocess.run = d
    try:
        sd.run_dc(V, "dc9", "net9", Env(), tries=tries)
        return "healthy", d
    except RuntimeError as e:
        return str(e), d


got, d = run([(["running starting", "exited unhealthy"], RACE), (["running starting", "running healthy"], "")])
check("lost the port race once: started again, then healthy", got == "healthy"
      and d.calls.count(["docker", "start"]) == 1, (got, d.calls))
got, d = run([(["running healthy"], "")])
check("healthy at once: never started again", got == "healthy" and ["docker", "start"] not in d.calls, d.calls)
got, d = run([(["exited unhealthy"], "ERROR: the join was refused\n")])
check("negative: an exit for another reason is not retried and fails, with the log",
      "not healthy" in got and "join was refused" in got and ["docker", "start"] not in d.calls, (got, d.calls))
got, d = run([(["exited unhealthy"], RACE)] * 5)
check("negative: losing the race three times fails (two starts again, no more)",
      "not healthy" in got and d.calls.count(["docker", "start"]) == 2, (got, d.calls))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
