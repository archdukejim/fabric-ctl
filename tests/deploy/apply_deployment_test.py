"""The deploy engine's order (2.3.10.11.16): Kea checks its files before anything of the apply is installed, so a
file Kea refuses changes nothing. Before, BIND's new zone list was installed first and never reconfigured, and the
next apply saw no change to reconfigure for. Pure logic: the engine's steps are stood in for (the kea suite runs
Kea's check for real, the lab the whole apply).
    python3 tests/deploy/apply_deployment_test.py"""
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


def run(kea_on, kea_refuses):
    """The engine with its steps stood in for; returns (steps in order, exit code or None, printed text)."""
    calls = []
    results = {"install_service_units": {"restart": set(), "stopped": set(), "rebuild": False,
                                         "daemon_reload": False},
               "install_nginx_config": {"daemon_reload": False, "nginx": False},
               "install_bind9_files": {"config": True, "zones": set()},
               "deploy_optional_parts": {"restart": set()},
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
                                                   "service_user")}
    for n in INSTALLS:
        setattr(ad, n, step(n))
    ad.render_deployment = lambda paths: {"secrets": {}, "final_vars": {"install_kea": kea_on}, "context":
                                          {"federation_links": []}, "jinja_env": None, "units": [],
                                          "tsig_keys": [], "dns_digest": None}
    ad.verify_published_images = lambda *a: False
    ad.check_kea_files = check_kea
    ad.restart_changed = lambda *a: (calls.append("restart_changed"), set())[1]
    ad.renew_landing_cert = lambda *a: False
    ad.allowed_to_change = lambda *a, **k: True
    ad.plan_services = lambda: []
    ad.deploy_paths = lambda: {"render": "/nonexistent", "base": "/nonexistent", "config": "/nonexistent",
                               "federation": "/nonexistent"}
    ad.service_user = lambda v, name: (0, 0)
    out, code = io.StringIO(), None
    try:
        with redirect_stdout(out):
            ad.apply_deployment()
    except SystemExit as e:
        code = e.code
    finally:
        for n, f in saved.items():
            setattr(ad, n, f)
    return calls, code, out.getvalue()


calls, code, out = run(kea_on=True, kea_refuses=True)
# covers: setting:dhcp -
check("negative: a Kea file Kea refuses stops the apply before anything is installed (no BIND files, no units), "
      "saying why", calls == ["check_kea_files"] and code == 1 and "Kea refused" in out, (calls, code, out))
calls, code, out = run(kea_on=True, kea_refuses=False)
check("positive: Kea's files checked first, then every step installed and the changed services restarted",
      calls[0] == "check_kea_files" and all(n in calls for n in INSTALLS) and calls[-1] == "restart_changed"
      and code is None, (calls, code))
calls, code, out = run(kea_on=False, kea_refuses=True)
check("positive: with DHCP off Kea's files are not checked", "check_kea_files" not in calls and code is None, calls)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
