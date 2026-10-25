import codecs
import os
import sys
import time

from fabriclib.common.console import err, info
from fabriclib.setup.detach.constants import LOG, UNIT
from fabriclib.setup.detach.read_run import read_run
from fabriclib.setup.detach.unit_running import unit_running

DETACHED = ("setup goes on as {unit}: a dropped connection or Ctrl-C does not stop it.\n"
            "    Follow it again: sudo fabricctl setup   (systemd's own lines: journalctl -u fabric-setup)")


def follow_run(config_dir, running=unit_running, out=None, sleep=time.sleep, interval=0.5, wait_log=10.0):
    """Purpose: show setup's run as it goes (decision 2.1.2.26, manual 1.3.2.3.2): print the run's log from its
             start and as it grows until the unit has ended, then end with the run's result. Ctrl-C stops
             following, never the work.
    Inputs:  config_dir — the install's config folder (setup-run.log, setup-run.yaml); running — callable() -> bool,
             whether the unit still runs (unit_running); out — text stream (default sys.stdout); sleep, interval —
             the pause between looks at the log (tests give their own); wait_log — seconds to wait for the log to
             appear.
    Returns: exit status: 0 when the record says done; the record's result when it says failed (1, or 130 when a
             step was interrupted); 1, saying so, when the unit ended without recording an end (its process was
             killed, or the log never appeared); 130 after Ctrl-C, saying the work goes on and how to follow it again.
    Fails:   OSError reading the log or the record other than its absence.
    Feeds:   setup/run_setup (re-attaching), detach/hand_over (after starting the unit)."""
    out = out or sys.stdout
    path = os.path.join(config_dir, LOG)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        waited = 0.0
        while not os.path.exists(path):
            if waited >= wait_log or not running():
                err(f"no log of setup's run at {path}: journalctl -u fabric-setup")
                return 1
            sleep(interval)
            waited += interval
        with open(path, "rb") as f:
            while True:
                chunk = f.read()
                if chunk:
                    out.write(decoder.decode(chunk))
                    out.flush()
                    continue
                if not running():
                    out.write(decoder.decode(f.read(), final=True))
                    out.flush()
                    break
                sleep(interval)
    except KeyboardInterrupt:
        out.write("\n")
        info(DETACHED.format(unit=UNIT))
        return 130
    record = read_run(config_dir) or {}
    if record.get("state") == "done":
        return 0
    if record.get("state") == "failed":
        return int(record.get("result") or 1)
    err(f"{UNIT} ended before setup finished (stopped or killed): journalctl -u fabric-setup; "
        "`sudo fabricctl setup` resumes from the step that did not finish")
    return 1
