"""An image switch waits for the services systemd restarts with the ones it moves (2.3.1.21.1): Keycloak behind
Postgres. Pure logic: the deploy, systemd and Docker are stubbed.
    python3 tests/images/switch_image_test.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
import fabriclib.images.switch_image as sw  # noqa: E402
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


class Ctx:
    target_dir = "/nonexistent"

    def __init__(self):
        self.vars = {}


POSTGRES = {"name": "postgres", "unit": "postgres", "container": "postgres", "var": "image_postgres"}
KEYCLOAK = {"name": "keycloak", "unit": "keycloak", "container": "keycloak", "var": "image_keycloak"}
NGINX = {"name": "nginx", "unit": "nginx", "container": "nginx", "var": "image_nginx"}


def run(services, installed, healthy=True):
    calls = {"started": [], "waited": []}
    sw.deploy_config.run = lambda ctx: None
    sw.start_unit = lambda unit, container, restart: calls["started"].append(unit)
    sw.installed_services = lambda ctx: installed
    sw.wait_healthy = lambda container, timeout: (calls["waited"].append(container) or (healthy, "unhealthy"))
    try:
        sw._apply(Ctx(), services[0]["var"], "x@sha256:" + "a" * 64, services)
        calls["error"] = None
    except SetupError as e:
        calls["error"] = str(e)
    return calls


r = run([POSTGRES], [POSTGRES, KEYCLOAK, NGINX])
check("postgres moved: keycloak, restarted with it by systemd, is waited for", r["waited"] == ["keycloak"]
      and r["started"] == ["postgres"] and r["error"] is None, r)
r = run([POSTGRES], [POSTGRES, NGINX])
check("postgres moved without keycloak installed: nothing else waited for", r["waited"] == [], r)
r = run([NGINX], [POSTGRES, KEYCLOAK, NGINX])
check("nginx moved: no dependent, nothing else waited for", r["waited"] == [], r)
r = run([KEYCLOAK], [POSTGRES, KEYCLOAK])
check("keycloak moved by itself: not waited for twice", r["waited"] == [] and r["started"] == ["keycloak"], r)
r = run([POSTGRES], [POSTGRES, KEYCLOAK], healthy=False)
check("keycloak not healthy again: the switch fails (and so rolls back), naming it",
      r["error"] and "keycloak" in r["error"] and "postgres" in r["error"], r)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
