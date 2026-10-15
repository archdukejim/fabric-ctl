import os
import subprocess
import sys

from fabriclib.setup.detach.constants import PASSED_ENV, UNIT
from fabriclib.setup.errors import SetupError

CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "cli.py")


def launch_worker(run_id, deploy_base, log, env=None, run=subprocess.run, cli=CLI):
    """Purpose: start setup's work as the transient unit fabric-setup.service (decision 2.1.2.26, manual 1.3.2.3):
             `systemd-run --unit fabric-setup --collect` running `fabricctl setup --worker <run>` with this same code,
             its output appended to the run's log, so a dropped session does not stop it.
    Inputs:  run_id — the run's id (in the record); deploy_base — the install root; log — the run's log file (it
             exists, 0600); env — the console's environment (default os.environ): only SUDO_USER and SSH_CONNECTION
             are passed (names, never secrets: the command line and the environment are what `systemctl show`
             prints to any user); run — subprocess.run (tests give their own); cli — the cli.py to run (this code's).
    Returns: None once systemd has started the unit's process (Type=exec).
    Fails:   SetupError naming systemd-run's message when it cannot start the unit (one by that name already loaded,
             systemd refusing); OSError when systemd-run is missing (can_detach checks first).
    Feeds:   detach/hand_over."""
    env = os.environ if env is None else env
    cmd = ["systemd-run", f"--unit={UNIT}", "--collect", "--quiet", "-p", "Type=exec",
           f"--description=fabric setup (run {run_id})",
           "-p", f"StandardOutput=append:{log}", "-p", f"StandardError=append:{log}",
           "--setenv=HOME=/root", "--setenv=PYTHONUNBUFFERED=1", "--setenv=PYTHONIOENCODING=utf-8"]
    cmd += [f"--setenv={k}={env[k]}" for k in PASSED_ENV if env.get(k)]
    cmd += ["--", sys.executable, cli, "setup", "--worker", run_id, "--deploy-base", deploy_base]
    r = run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SetupError(f"could not start {UNIT}: {(r.stderr or r.stdout or '').strip() or 'systemd-run failed'}")
