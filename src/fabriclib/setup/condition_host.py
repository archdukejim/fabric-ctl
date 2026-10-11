import subprocess
import time

from fabriclib.common.console import info, ok
from fabriclib.common.run import run as sh
from fabriclib.consent.check_consent import check_consent
from fabriclib.consent.plan_packages import DOCKER_PACKAGES, plan_packages
from fabriclib.setup.common.apt_install import apt_install
from fabriclib.setup.common.missing_packages import missing_packages
from fabriclib.setup.errors import SetupError

DOCKER_CE = "docker-ce"     # Docker's own package: kept when an install already runs it, never installed


def run(ctx):
    """Purpose: host packages and Docker Engine with compose v2 and buildx (Ubuntu's docker.io; an existing
             docker-ce install is kept), running and enabled — all from the host's own apt sources, after the
             `packages` consent (manual 1.2.9).
    Inputs:  ctx — SetupContext: offline (never download), config_dir (consent.yaml).
    Returns: None; missing packages installed, Docker installed if needed, docker.service enabled and answering
             `docker info`. Idempotent: nothing is installed when present. No apt source or key is added.
    Fails:   SetupError: the packages not approved; offline with packages or Docker missing; apt install failure
             (with advice on apt sources); Docker not answering after about 60 s. CommandError from
             `apt-get update`, `systemctl enable --now docker` or the version queries propagates.
    Feeds:   setup step `host`, run by run_setup via STEPS."""
    plan = plan_packages()
    if plan["text"]:
        if ctx.offline:
            raise SetupError(f"offline install but packages are missing: {' '.join(plan['host'] + plan['docker'])}")
        check_consent(ctx.config_dir, "packages", plan["text"])
    if plan["host"]:
        info(f"installing {' '.join(plan['host'])}")
        apt_install(plan["host"], "If apt reports unmet dependencies or held broken packages, the host's apt sources "
                                   "are usually incomplete (e.g. missing <release>-updates, which the installed "
                                   "libraries came from). Fix the sources, run `apt-get update`, then re-run setup.")
    ok("host packages present")

    if plan["docker"]:
        info(f"installing Docker Engine from the Ubuntu archive ({' '.join(DOCKER_PACKAGES)})")
        apt_install(plan["docker"], "They are in Ubuntu's universe component: check that the host's apt sources "
                                     "include universe, run `apt-get update`, then re-run setup.")
    elif not missing_packages([DOCKER_CE]):
        info("Docker comes from Docker's own repository (docker-ce): kept as it is. New hosts get Ubuntu's "
             "docker.io; to switch, see the manual, 3.2.2 (Docker from the Ubuntu archive)")
    sh(["systemctl", "enable", "--now", "docker"])
    for _ in range(12):
        if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
            break
        time.sleep(5)
    else:
        raise SetupError("Docker is installed but not responding (docker info)")
    ok(sh(["docker", "version", "-f", "Docker {{.Server.Version}}"]).stdout.strip()
       + ", " + sh(["docker", "compose", "version", "--short"]).stdout.strip().join(["compose ", ""]))
