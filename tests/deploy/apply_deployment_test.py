"""The deploy engine's order (2.3.10.11.16): Kea checks its files before anything of the apply is installed, so a
file Kea refuses changes nothing. Before, BIND's new zone list was installed first and never reconfigured, and the
next apply saw no change to reconfigure for. Kea's changed files are reloaded, not restarted, unless its unit
changed or nothing is started (2.1.10.45), and the whole apply holds the apply intent. Pure logic: the engine's
steps are stood in for (the kea suite runs
Kea's check for real, the lab the whole apply).
    python3 tests/deploy/apply_deployment_test.py"""
import contextlib
import io
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.deploy.apply_deployment as ad  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402

PASS = FAIL = 0
INSTALLS = ("install_fabric_tree", "install_service_units", "install_openbao_config", "install_nginx_config",
            "install_bind9_files", "deploy_optional_parts", "install_webui_files", "deploy_federation_endpoint",
            "install_stepca_templates", "install_runtime_dirs", "install_timers", "keep_hand_set_addresses")


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


STATES = []


def run(kea_on, kea_refuses, kea_files=frozenset(), unit_restart=frozenset(), start=True):
    """The engine with its steps stood in for; returns (steps in order, exit code or None, printed text); the state
    restart_changed (or finish_without_start) was given is the last of STATES."""
    calls = []
    results = {"install_service_units": {"restart": set(unit_restart), "stopped": set(), "rebuild": False,
                                         "daemon_reload": False},
               "install_nginx_config": {"daemon_reload": False, "nginx": False},
               "install_bind9_files": {"config": True, "zones": set()},
               "deploy_optional_parts": {"restart": set(), "kea": set(kea_files)},
               "install_webui_files": {"agent": False, "webui": False},
               "deploy_federation_endpoint": {"unit_changed": False, "removed": False}}

    def step(name):
        def f(*a, **k):
            calls.append(name)
            return results.get(name, False)
        return f

    def check_kea(*a, **k):
        calls.append("check_kea_files")
        if kea_refuses:
            raise ValidationError("Kea refused the new kea-dhcp4.conf: bad — nothing was changed")
        return {}

    saved = {n: getattr(ad, n) for n in INSTALLS + ("render_deployment", "verify_published_images",
                                                   "check_kea_files", "restart_changed", "renew_landing_cert",
                                                   "allowed_to_change", "plan_services", "deploy_paths",
                                                   "service_user", "apply_intent", "finish_without_start")}
    for n in INSTALLS:
        setattr(ad, n, step(n))
    ad.render_deployment = lambda paths, rotate=False: {"secrets": {}, "final_vars": {"install_kea": kea_on}, "context":
                                          {"federation_links": []}, "jinja_env": None, "units": [],
                                          "tsig_keys": [], "dns_digest": None, "kea_old": None}
    ad.verify_published_images = lambda *a: False
    ad.check_kea_files = check_kea
    ad.restart_changed = lambda *a: (calls.append("restart_changed"), STATES.append(a[3]), set())[2]
    ad.finish_without_start = lambda paths, state, ids: (calls.append("finish_without_start"), STATES.append(state),
                                                         set())[2]

    @contextlib.contextmanager
    def intent():
        calls.append("intent held")
        try:
            yield
        finally:
            calls.append("intent let go")
    ad.apply_intent = intent
    ad.renew_landing_cert = lambda *a: False
    ad.allowed_to_change = lambda *a, **k: True
    ad.plan_services = lambda: []
    ad.deploy_paths = lambda: {"render": "/nonexistent", "base": "/nonexistent", "config": "/nonexistent",
                               "federation": "/nonexistent"}
    ad.service_user = lambda v, name: (0, 0)
    out, code = io.StringIO(), None
    try:
        with redirect_stdout(out):
            ad.apply_deployment(start_services=start)
    except SystemExit as e:
        code = e.code
    finally:
        for n, f in saved.items():
            setattr(ad, n, f)
    return calls, code, out.getvalue()


calls, code, out = run(kea_on=True, kea_refuses=True)
# covers: setting:dhcp -
check("negative: a Kea file Kea refuses stops the apply before anything is installed (no BIND files, no units), "
      "saying why", calls == ["intent held", "check_kea_files", "intent let go"] and code == 1
      and "Kea refused" in out, (calls, code, out))
calls, code, out = run(kea_on=True, kea_refuses=False)
check("positive: Kea's files checked first, then every step installed and the changed services restarted, all "
      "under the apply intent (2.1.10.45)", calls[0] == "intent held" and calls[1] == "check_kea_files"
      and all(n in calls for n in INSTALLS) and calls[-2:] == ["restart_changed", "intent let go"]
      and code is None, (calls, code))
calls, code, out = run(kea_on=True, kea_refuses=False, kea_files={"kea-dhcp4.conf"})
check("positive: a changed Kea file is reloaded after BIND (state kea_reload), Kea not restarted (2.1.10.45)",
      STATES[-1]["kea_reload"] == {"kea-dhcp4.conf"} and "kea" not in STATES[-1]["restart"], STATES[-1])
calls, code, out = run(kea_on=True, kea_refuses=False, kea_files={"kea-dhcp4.conf"}, unit_restart={"kea"})
check("negative: Kea's unit changed too: restarted on the new file, no reload asked",
      not STATES[-1]["kea_reload"] and "kea" in STATES[-1]["restart"], STATES[-1])
calls, code, out = run(kea_on=True, kea_refuses=False, kea_files={"kea-dhcp-ddns.conf"}, start=False)
check("negative: nothing started (setup's deploy): Kea is left for setup's start step, no reload asked",
      "finish_without_start" in calls and not STATES[-1]["kea_reload"] and "kea" in STATES[-1]["restart"],
      (calls, STATES[-1]))
calls, code, out = run(kea_on=True, kea_refuses=True)
check("negative: a refused apply lets the apply intent go too", calls[-1] == "intent let go" and code == 1, calls)
calls, code, out = run(kea_on=False, kea_refuses=True)
check("positive: with DHCP off Kea's files are not checked", "check_kea_files" not in calls and code is None, calls)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
