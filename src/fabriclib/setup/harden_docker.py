import json
import os
import subprocess
import time

from fabriclib.common.systemctl_up import systemctl_up
from fabriclib.common.console import info, ok, warn
from fabriclib.common.keep_original import keep_original
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_runtime import plan_runtime
from fabriclib.security.hardened_daemon_settings import DAEMON_JSON, HARDENED, hardened_daemon_settings
from fabriclib.setup.errors import SetupError


def run(ctx):
    """Purpose: merge the HARDENED settings into /etc/docker/daemon.json (existing keys kept) and restart Docker
             if anything changed.
    Inputs:  ctx — SetupContext: vars security.docker_daemon_hardening (default True), config_dir (the `runtime`
             consent: without it nothing is written). Reads DAEMON_JSON.
    Returns: None; daemon.json converged (its earlier content kept once, common/keep_original) and Docker
             restarted only when it changed. With the setting false it
             only warns — settings written earlier are not removed.
    Fails:   json.JSONDecodeError on an unparseable daemon.json; CalledProcessError from `systemctl restart
             docker`; SetupError when Docker does not answer `docker info` within about 60 s; AttributeError
             if vars `security` is null.
    Feeds:   setup step `docker`, run by run_setup via STEPS.
    Notes:   no-new-privileges, no icc on the default bridge, no userland proxy, live-restore, bounded logs."""
    if not ctx.vars.get("security", {}).get("docker_daemon_hardening", True):
        warn("Docker daemon hardening disabled (security.docker_daemon_hardening: false)")
        return
    current, merged = hardened_daemon_settings()
    if merged == current:
        ok("Docker daemon already hardened")
        return
    if not check_consent(ctx.config_dir, "runtime", plan_runtime(ctx.vars)):
        return
    keep_original(DAEMON_JSON, ctx.config_dir)          # `setup --undo runtime` puts it back
    os.makedirs(os.path.dirname(DAEMON_JSON), exist_ok=True)
    with open(DAEMON_JSON, "w") as f:
        json.dump(merged, f, indent=2)
        f.write("\n")
    info("restarting Docker to apply daemon settings (live-restore keeps containers running from now on)")
    systemctl_up(["docker"], restart=True)
    for _ in range(12):
        if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
            ok("Docker daemon hardened: " + ", ".join(k for k in HARDENED if k != "log-driver"))
            return
        time.sleep(5)
    raise SetupError(f"Docker did not come back after applying {DAEMON_JSON}; check `journalctl -u docker`")
