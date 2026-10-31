"""The apply's measured rollout (2.1.14.15, manual 1.14.2.11): the changed services restarted one at a time in
dependency order, each health-gated, the rollout stopped at the first that is not healthy, naming it and what was
not restarted. Pure logic: systemd and the containers are stood in for (the sandbox runs the real thing).
    python3 tests/deploy/restart_changed_test.py"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.deploy.restart_changed as rc  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
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


def run(restart, unhealthy=(), inactive=()):
    """The rollout with start_unit and systemctl stood in for; returns (units restarted in order, error or None)."""
    done = []

    def start_unit(unit, container, restart):
        done.append(unit)
        if unit in unhealthy:
            raise SetupError(f"{container} did not become healthy (unhealthy)")
        return "restarted"

    def sysrun(cmd, **kw):
        if cmd[1] == "restart":
            done.append(cmd[2])
        return subprocess.CompletedProcess(cmd, 3 if cmd[-1] in inactive and "is-active" in cmd else 0)

    rc.start_unit, real_run = start_unit, rc.subprocess.run
    rc.subprocess.run = sysrun
    try:
        rc._roll_out(set(restart))
        return done, None
    except ValidationError as e:
        return done, str(e)
    finally:
        rc.subprocess.run = real_run


done, err = run({"bind9-resolver", "nginx", "keycloak", "postgres", "bind9", "openbao"})
check("positive: every changed service restarted once, in dependency order (OpenBao, BIND, Postgres, Keycloak, "
      "nginx, the resolver)", done == ["openbao", "bind9", "postgres", "keycloak", "nginx", "bind9-resolver"]
      and err is None, (done, err))
done, err = run({"chrony", "nginx"})
check("positive: a unit fabric does not order (a host service) goes last, checked active",
      done == ["nginx", "chrony"] and err is None, (done, err))
done, err = run(set())
check("positive: nothing changed, nothing restarted", done == [] and err is None, (done, err))
done, err = run({"postgres", "keycloak", "nginx"}, unhealthy={"postgres"})
check("negative: Postgres not healthy stops the rollout there: Keycloak and nginx are not restarted, and the "
      "error names them", done == ["postgres"] and err and "postgres did not come back healthy" in err
      and "keycloak, nginx not restarted" in err, (done, err))
done, err = run({"nginx", "chrony"}, inactive={"chrony"})
check("negative: a host service not active after its restart is refused the same way",
      done == ["nginx", "chrony"] and err and "chrony did not come back healthy" in err, (done, err))



def finish(names, flush_result):
    """restart_changed on a running install where only zones changed: docker, systemd and the resolver's flush stood
    in for. Returns (what the flush was asked, the printed output)."""
    import contextlib
    import io
    asked = []

    def sysrun(cmd, **kw):
        out = "bind9\nbind9-resolver\n" if cmd[:2] == ["docker", "ps"] else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")

    real_run, real_flush, real_reload = rc.subprocess.run, rc.flush_published_names, rc.reload_zone
    rc.subprocess.run = sysrun
    rc.flush_published_names = lambda v, changed: asked.append(changed) or flush_result
    rc.reload_zone = lambda *a: None
    state = {"restart": set(), "rebuild": set(), "daemon_reload": False, "bind9_config": False,
             "zones": [("lan.test", "/r/db.lan.test", "/d/db.lan.test")], "nginx": False, "webui": False,
             "agent": False, "federation_unit": False, "names": names}
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            rc.restart_changed({"base": "/x"}, {"install_resolver": True}, {}, state, (600, 600))
    finally:
        rc.subprocess.run, rc.flush_published_names, rc.reload_zone = real_run, real_flush, real_reload
    return asked, out.getvalue()


changed = {"names": ["late.lan.test."], "trees": []}
asked, out = finish(changed, {"flushed": 1, "error": None})
check("positive: once BIND serves the changed zone the filtering resolver forgets the changed names (2.1.4.9), and "
      "the apply says how many", asked == [changed] and "1 published name(s) flushed" in out, (asked, out))
asked, out = finish(changed, {"flushed": 0, "error": "the filtering resolver did not forget late.lan.test (x)"})
check("negative: a flush that fails is a warning, the apply goes on to its end",
      "Warning: the filtering resolver did not forget late.lan.test" in out and "Deployment complete." in out, out)
asked, out = finish({"names": [], "trees": []}, {"flushed": 0, "error": None})
check("no name changed: nothing flushed, nothing said (flush_published_names asks rndc nothing then)",
      "flushed" not in out and "Warning" not in out, (asked, out))

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
