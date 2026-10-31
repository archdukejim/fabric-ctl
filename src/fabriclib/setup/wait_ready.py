import os
import subprocess
import time

from fabriclib.common.console import info, ok
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.setup.errors import SetupError

QUIET = 30                       # seconds Postgres's log must stay free of refused sign-ins
TIMEOUT = 300                    # how long setup waits for everything to answer at once
REFUSED = ("not permitted to log in", "password authentication failed")


def _code(url, name, ip, port, cafile):
    """Purpose: the HTTP status of one URL, reached at ip:port under its name (curl --resolve), the certificate
             checked against fabric's root when cafile is given.
    Inputs:  url — str; name — the URL's host name; ip, port — where it is served; cafile — path or None.
    Returns: str, the status ("200"), or "curl exit <n>".
    Fails:   never (curl missing reads as its exit code).
    Feeds:   probes."""
    res = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10",
                          *(["--cacert", cafile] if cafile else []), "--resolve", f"{name}:{port}:{ip}", url],
                         capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else f"curl exit {res.returncode}"


def _refusals(since):
    """Purpose: how many sign-ins Postgres refused in the last `since` seconds (its log).
    Inputs:  since — int seconds.
    Returns: int.
    Fails:   never (no container reads as none).
    Feeds:   probes."""
    res = subprocess.run(["docker", "logs", "--since", f"{since}s", "postgres"], capture_output=True, text=True)
    text = res.stdout + res.stderr
    return sum(text.count(r) for r in REFUSED)


def probes(ctx):
    """Purpose: what a person reaches first after setup, as (name, probe) pairs: the landing page by address, the
             sign-in (Keycloak's realm through nginx, its certificate checked), the web console, and Keycloak's
             database settled (no refused sign-in in Postgres's log for QUIET seconds).
    Inputs:  ctx — SetupContext: vars host_ip, ip_nginx, hostname_keycloak, webui_realm, hostname_mgr,
             webui_client_cert, install_keycloak, install_webui; the Step-CA root certificate.
    Returns: list of (str, callable() -> bool).
    Fails:   never.
    Feeds:   run."""
    v = ctx.vars
    root_ca = ctx.path("stepca", "data", "certs", "root_ca.crt")
    checks = [("the landing page, http://%s/info/" % v["host_ip"],
               lambda: _code(f"http://{v['host_ip']}/info/", v["host_ip"], v["host_ip"], 80, None) == "200")]
    if v.get("install_keycloak"):
        realm = f"https://{v['hostname_keycloak']}/realms/{v.get('webui_realm') or v['domain']}"
        discovery = f"{realm}/.well-known/openid-configuration"
        checks.append((f"sign-in, {realm}",
                       lambda: _code(discovery, v["hostname_keycloak"], v["ip_nginx"], 443, root_ca) == "200"))
        checks.append((f"Keycloak's database: no refused sign-in in Postgres's log for {QUIET} s",
                       lambda: _refusals(QUIET) == 0))
    if v.get("install_webui"):
        want = "400" if v.get("webui_client_cert") else "303"       # as doctor: a certificate asked, or sign-in
        checks.append((f"the web console, https://{v['hostname_mgr']}/",
                       lambda: _code(f"https://{v['hostname_mgr']}/", v["hostname_mgr"], v["ip_nginx"], 443,
                                     root_ca) == want))
    return checks


def wait_ready(checks, timeout=TIMEOUT, interval=5, clock=time.monotonic, sleep=time.sleep):
    """Purpose: wait until every check passes in the same round.
    Inputs:  checks — list of (name, probe); timeout, interval — seconds; clock, sleep — for tests.
    Returns: [] once all pass together, else the names still failing when the time is up.
    Fails:   whatever a probe raises.
    Feeds:   run."""
    deadline = clock() + timeout
    while True:
        failing = [name for name, probe in checks if not probe()]
        if not failing or clock() >= deadline:
            return failing
        sleep(interval)


def run(ctx):
    """Purpose: setup's last gate (decision 2.1.2.25): "fabric is ready" and the first steps are printed only once
             what a person reaches first answers, all at once, and Keycloak's database has settled.
    Inputs:  ctx — SetupContext (see probes).
             Once ready, the install records it (install_was_ready, 2.1.4.10): from then on the landing page's alias
             is the admin's record, no longer added by a render.
    Returns: None.
    Fails:   SetupError naming what did not answer within TIMEOUT s; `sudo fabricctl doctor` to look again.
             OSError or yaml.YAMLError recording it.
    Feeds:   setup step `ready`, run by run_setup via STEPS (after verify)."""
    checks = probes(ctx)
    info(f"waiting for {len(checks)} thing(s) to answer at once (up to {TIMEOUT // 60} min)")
    failing = wait_ready(checks, timeout=TIMEOUT)
    if failing:
        raise SetupError("not ready: " + "; ".join(failing) + f" (still failing after {TIMEOUT // 60} min; "
                         "look again with sudo fabricctl doctor)")
    for name, _ in checks:
        ok(name)
    if not ctx.vars.get("install_was_ready", True) and os.path.exists(ctx.vars_file):
        with vars_lock(os.path.join(ctx.config_dir, ".vars.lock")):
            data = load_vars(ctx.vars_file)
            data["install_was_ready"] = True
            save_vars(data, ctx.vars_file)
        ctx.vars["install_was_ready"] = True
