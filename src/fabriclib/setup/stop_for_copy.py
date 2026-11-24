import os
import subprocess
import time

from fabriclib.common.errors import ValidationError
from fabriclib.setup.uninstall import DIRS, TIMERS
from fabriclib.system.control_stack import control_stack

STOP_WAIT = 90              # seconds the containers get to be gone once their units have stopped (2.3.1.53)


def _still_running(base):
    """Purpose: the containers of this install still running, whatever systemd says of their units.
    Inputs:  base — the install's deploy base; Compose records each project's folder on its containers.
    Returns: sorted [name]; only those of fabric's own folders (DIRS): another project, even in the same base, is not.
    Fails:   ValidationError when Docker cannot say: an export must not assume.
    Feeds:   stop_for_copy."""
    res = subprocess.run(["docker", "ps", "--format",
                          '{{.Names}}\t{{.Label "com.docker.compose.project.working_dir"}}'],
                         capture_output=True, text=True)
    if res.returncode != 0:
        raise ValidationError(f"the export could not ask Docker what is running: {res.stderr.strip()[:300]}. "
                              "Nothing was uninstalled")
    rows = (line.split("\t") + [""] for line in res.stdout.splitlines())
    folders = {os.path.join(base, name) for name in DIRS}
    return sorted(row[0] for row in rows if row[1] in folders)


def stop_for_copy(base):
    """Purpose: stop fabric and prove it has stopped before anything is copied. `systemctl stop fabric.target` returned
             in under a second with Postgres still running: a unit is ordered Before= the target, so the target's stop
             ends first and the units' stops, which systemctl does not wait for, come after (2.3.1.53).
    Inputs:  base — the install's deploy base.
    Returns: None. Nothing of this install is running, and no timer of fabric's can start anything during the copy.
    Fails:   ValidationError from control_stack, or when a container of this install is still running after STOP_WAIT:
             the copy would not be consistent, so there is none.
    Feeds:   backup/make_backup (a cold bundle: uninstall, reinstall)."""
    # one that is not there is no failure
    subprocess.run(["systemctl", "stop", *[f"{t}.timer" for t in TIMERS]], capture_output=True)
    control_stack("stop")                          # names every unit, so systemctl waits for each
    end = time.time() + STOP_WAIT
    running = _still_running(base)
    while running and time.time() < end:
        time.sleep(1)
        running = _still_running(base)
    if running:
        raise ValidationError(f"fabric did not stop: {', '.join(running)} still running after {STOP_WAIT} s. A copy "
                              "now would not be consistent, so there is none, and nothing was uninstalled")
