#!/usr/bin/env python3
"""The sizing advice with no container (manual 1.8.8.8, decision 2.1.8.36): the model's arithmetic against the published
table, an alert at, just below and just above each threshold for each resource, a dismissal kept and its return at the
next 10% step and at a warn-to-critical crossing, whose dismissal it is, the agent's routes and their permission,
`fabricctl sizing`, and what `status` and `doctor` print. The DC is a stub here; the sandbox and the `samba` suite read
the real one (tests/samba/domain.py).

    python3 tests/sizing/run.py
"""
import contextlib
import io
import json
import os
import sys
import tempfile
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src")]
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402
from fabriclib.sizing.advice import RESOURCES, needed, objects_of, sizing_alerts, visible_alerts  # noqa: E402
import fabriclib.sizing.refresh_sizing as m_refresh  # noqa: E402
from fabriclib.sizing.run_sizing_command import run_sizing_command, show_sizing  # noqa: E402
from fabriclib.sizing.state import dismiss_alert, read_sizing  # noqa: E402
from fabriclib.sizing.table import TABLE  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))


SIZE = {"people": 1000, "computers": 500, "groups": 100}
N = 1600
LINE = {"ram": {"min": 1000, "min_per": 1.0, "rec": 2000, "rec_per": 2.0},
        "cores": {"min": 2, "min_per": 0.0, "rec": 3, "rec_per": 0.001},
        "disk": {"min": 100, "min_per": 0.5, "rec": 200, "rec_per": 1.0},
        "dc_memory": {"min": 50, "min_per": 0.1, "rec": 100, "rec_per": 0.2}}
want = needed(SIZE, LINE)
check("the model: a fixed part plus a part per directory object, for each resource",
      objects_of(SIZE) == N and want == {"ram": (2600, 5200), "cores": (2, 5), "disk": (900, 1800),
                                         "dc_memory": (210, 420)}, want)
small, large = needed({"people": 5}), needed({"people": 5000, "computers": 2500, "groups": 500})
check("the published table: recommended above minimum for each resource, growing with the install",
      all(small[r][0] <= small[r][1] and large[r][1] >= small[r][1] for r in RESOURCES) and set(TABLE) == set(RESOURCES),
      (small, large))
for res in RESOURCES:
    low, high = want[res]
    enough = {r: want[r][1] for r in RESOURCES}
    for have, level in ((high + 1, None), (high, None), (high - 1, "warn"), (low, "warn"), (low - 1, "critical")):
        rows = sizing_alerts(SIZE, {**enough, res: have}, LINE)
        got = [a["level"] for a in rows if a["resource"] == res]
        check(f"{res} at {have} (minimum {low}, recommended {high}): {level or 'no alert'}",
              got == ([level] if level else []) and len(rows) == len(got), rows)
one = sizing_alerts(SIZE, {"ram": 8192, "cores": None, "disk": None}, {**LINE, "ram": {
    "min": 1000, "min_per": 0.0, "rec": 13619, "rec_per": 0.0}})[0]
check("the alert names the numbers and the gap, as the owner's example, and what would close it",
      one["what"].startswith("1,000 people on 8.0 GB RAM: 5.3 GB below the recommended 13.3 GB for that size")
      and one["close"] == "add memory to the host" and one["gap"] == 13619 - 8192, one)
check("negative: what the host could not say gives no alert, never a guess",
      sizing_alerts(SIZE, {r: None for r in RESOURCES}, LINE) == [] and sizing_alerts(SIZE, {}, LINE) == [])
both = sizing_alerts(SIZE, {"ram": 1, "disk": 1000}, LINE)
check("critical first", [a["level"] for a in both] == ["critical", "warn"], both)

warn = [{"resource": "ram", "level": "warn"}]
crit = [{"resource": "ram", "level": "critical"}]
mark = {"ram": {"level": "warn", "objects": 100}}
check("a dismissal: the alert stays away while nothing new is to say", visible_alerts(warn, mark, {"people": 100}) == [])
check("...and at just under another 10%", visible_alerts(warn, mark, {"people": 109}) == [])
check("...it comes back at another 10% of the install's size", visible_alerts(warn, mark, {"people": 110}) == warn)
check("...and at a warn-to-critical crossing, at the same size", visible_alerts(crit, mark, {"people": 100}) == crit)
check("...dismissed at critical: critical at the same size stays away",
      visible_alerts(crit, {"ram": {"level": "critical", "objects": 100}}, {"people": 100}) == [])
check("...a very small install: at least one more object", visible_alerts(warn, {
    "ram": {"level": "warn", "objects": 0}}, {"people": 1}) == warn)

with tempfile.TemporaryDirectory() as config:
    v = {"deploy_base_dir": config, "memory_plan": {"limits": {"samba": 512}}}
    check("before the timer's first run: no alerts, no failure", read_sizing(config)["at"] == ""
          and read_sizing(config, "alice")["alerts"] == [])
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        show_sizing(config)
    check("...`status` and `doctor` say it is not worked out yet", "not worked out yet" in stdout.getvalue(),
          stdout.getvalue())

    def fake_op(_v, _s, op, args, container):
        assert op == "directory_size"
        return {"people": 900000, "computers": 0, "groups": 0}

    with mock.patch.object(m_refresh, "run_op", fake_op), mock.patch.object(m_refresh, "load_secrets", lambda: {}):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = run_sizing_command(v, config, ["refresh"])
        # covers: cli:sizing +
        # covers: cli:sizing.refresh +
        check("fabricctl sizing refresh: the size from the DC, the host's resources, written; says what it found",
              code == 0 and "900000 people" in stdout.getvalue() and "CRITICAL" in stdout.getvalue(), stdout.getvalue())
    stored = json.load(open(os.path.join(config, "sizing.json")))
    check("...the result on the host, with the time it was worked out", stored["at"] and stored["host"]["cores"]
          and stored["host"]["dc_memory"] == 512, stored)
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        code = run_sizing_command(v, config, ["show"])
    # covers: cli:sizing.show +
    check("fabricctl sizing show: the same alerts as the console, each with what would close it", code == 0
          and "to close it:" in stdout.getvalue() and "900,000 people on" in stdout.getvalue(), stdout.getvalue())
    for args in ([], ["frob"], ["show", "extra"], ["refresh", "extra"]):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = run_sizing_command(v, config, args)
        # covers: cli:sizing -
        # covers: cli:sizing.show cli:sizing.refresh -
        check(f"fabricctl sizing {' '.join(args)}: usage", code == 2 and "usage" in stdout.getvalue(), stdout.getvalue())

    def no_dc(*a):
        raise ValidationError("the domain controller is not running")

    before = open(os.path.join(config, "sizing.json")).read()
    with mock.patch.object(m_refresh, "run_op", no_dc), mock.patch.object(m_refresh, "load_secrets", lambda: {}):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = run_sizing_command(v, config, ["refresh", "--scheduled"])
    # covers: cli:sizing.refresh -
    check("negative: the DC not running: refused, saying why, the last result kept", code == 1
          and "not running" in stdout.getvalue() and open(os.path.join(config, "sizing.json")).read() == before,
          stdout.getvalue())

    first = read_sizing(config, "alice")["alerts"]
    res = first[0]["resource"]
    out = dismiss_alert(config, "alice", res)
    check("a dismissal is recorded with the level and the size", out["resource"] == res and out["objects"] == 900000, out)
    check("...it is the person's own: gone for alice, still there for bob and on the host's commands",
          res not in [a["resource"] for a in read_sizing(config, "alice")["alerts"]]
          and res in [a["resource"] for a in read_sizing(config, "bob")["alerts"]]
          and res in [a["resource"] for a in read_sizing(config)["alerts"]])
    try:
        dismiss_alert(config, "alice", "nonsense")
        why = ""
    except ValidationError as e:
        why = str(e)
    check("negative: dismissing what is not an alert now is refused, nothing recorded", "no sizing alert" in why, why)

    # the agent's routes
    from agent import post_sizing as m_post  # noqa: E402
    import agent.get_route as m_get  # noqa: E402
    audited = []
    with mock.patch.object(m_post, "load_vars", lambda: {"deploy_base_dir": os.path.dirname(os.path.dirname(config))}), \
            mock.patch.object(m_post, "write_audit", lambda *a, **k: audited.append(a)), \
            mock.patch.object(m_post, "dismiss_alert", lambda c, u, r: {"resource": r, "level": "warn", "objects": 1}):
        done = m_post.post_sizing("carol", {"resource": "ram"})
        # covers: agent:post.sizing.dismiss +
        check("POST /v1/sizing/dismiss: the person's, audited SIZING_DISMISS", done["resource"] == "ram"
              and audited and audited[0][:2] == ("carol", "SIZING_DISMISS"), audited)
        for body, who, words in (({}, "carol", "resource"), ({"resource": 3}, "carol", "resource"),
                                 ({"resource": "ram"}, "", "signed-in person")):
            try:
                m_post.post_sizing(who, body)
                why = ""
            except ValidationError as e:
                why = str(e)
            # covers: agent:post.sizing.dismiss -
            check(f"POST /v1/sizing/dismiss refused ({words})", words in why, why)
    # covers: agent:get.sizing +
    check("GET /v1/sizing and POST /v1/sizing/dismiss need status:read",
          required_permission("GET", ["sizing"]) == "status:read"
          and required_permission("POST", ["sizing", "dismiss"]) == "status:read")
    # covers: agent:get.sizing -
    check("negative: another route under sizing is refused (default deny)",
          required_permission("POST", ["sizing"]) is None and required_permission("GET", ["sizing", "x"]) is None)
    with mock.patch.object(m_get, "load_vars", lambda: {"deploy_base_dir": "/x"}), \
            mock.patch.object(m_get, "read_sizing", lambda c, u: {"config": c, "user": u}):
        got = m_get.get_route(["sizing"], "dave")
    check("...GET /v1/sizing reads the file, for the signed-in person", got == {"config": "/x/fabric/config",
                                                                                "user": "dave"}, got)

print(f"{'FAILED ' + str(FAILED) if FAILED else 'all passed'}")
sys.exit(1 if FAILED else 0)
