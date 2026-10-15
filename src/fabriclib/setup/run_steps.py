import datetime
import os
import time

import yaml

from fabriclib.common.console import BOLD, NC, err, heading
from fabriclib.setup.errors import SetupError
from fabriclib.setup.print_first_steps import print_first_steps


def _now():
    """Purpose: the time now, for the run record.
    Inputs:  none.
    Returns: ISO 8601 local time with its offset, seconds (str).
    Fails:   never.
    Feeds:   run_steps."""
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _save_settings(ctx):
    """Purpose: keep the settings the steps before deploy work from (the join step adds the organisation's) in
             fabric.yaml, as deploy itself does first, so a run resumed before deploy starts from them.
    Inputs:  ctx — SetupContext: vars, config_dir.
    Returns: None; <config>/fabric.yaml rewritten (0640).
    Fails:   OSError writing; yaml errors for values YAML cannot dump.
    Feeds:   run_steps."""
    path = os.path.join(ctx.config_dir, "fabric.yaml")
    with open(path, "w") as f:
        yaml.safe_dump(ctx.vars, f, sort_keys=False)
    os.chmod(path, 0o640)


def run_steps(ctx, steps, selected, guided=False, record=None, save=None):
    """Purpose: run setup's steps in order, then say fabric is ready with the first steps (manual 3.3.3); with a run
             record, keep it current after each step so a stopped run can be resumed from the first step that did
             not finish (decision 2.1.2.26, manual 1.3.2.3.3).
    Inputs:  ctx — SetupContext (vars loaded as the first step needs them: collected settings before deploy, the
             rendered vars after); steps — STEPS, [(name, function, description)]; selected — the step names to run;
             guided — the run began Guided (print_first_steps); record — the run's record (dict) or None for a
             `--step` run (nothing recorded); save — callable(record), write_run bound to the config folder (with a
             record).
    Returns: exit status: 0 done, 1 a SetupError (its message printed, and how to go on when recorded), 130
             interrupted. With a record: its done list grows by each finished step, current names the step running,
             restart_services holds the services to restart (deploy, pki and certs add to it; start restarts them);
             at the end state is "done" or "failed" with result and finished. Before deploy, each step's settings are
             saved to fabric.yaml. After deploy, the rendered vars are reloaded.
    Fails:   any exception other than SetupError/KeyboardInterrupt from a step propagates (a traceback), the record
             first marked failed with result 1.
    Feeds:   setup/run_setup (`--step` runs; a full run where systemd cannot run it), detach/run_worker (the unit)."""
    start = time.monotonic()
    deploy_ahead = "deploy" in selected and not (record and "deploy" in (record.get("done") or []))

    def mark(**fields):
        if record is not None:
            record.update(fields)
            save(record)

    try:
        for name, step, desc in steps:
            if name not in selected:
                continue
            mark(current=name)
            heading(f"[{name}] {desc}")
            step(ctx)
            if name == "deploy":
                ctx.load_state()
                deploy_ahead = False
            elif deploy_ahead and record is not None:
                _save_settings(ctx)
            if record is not None:
                mark(done=[*(record.get("done") or []), name], restart_services=sorted(ctx.restart_services))
        heading(f"{BOLD}fabric is ready{NC} ({time.monotonic() - start:.0f}s)")
        print_first_steps(ctx, guided=guided)
        mark(state="done", result=0, current=None, finished=_now())
        return 0
    except SetupError as e:
        err(str(e))
        if record is not None:
            err(f"stopped at [{record.get('current')}]: fix what it says, then `sudo fabricctl setup` resumes from "
                "there (--restart asks the questions again)")
        mark(state="failed", result=1, finished=_now())
        return 1
    except KeyboardInterrupt:
        err("interrupted")
        mark(state="failed", result=130, finished=_now())
        return 130
    except BaseException:
        mark(state="failed", result=1, finished=_now())
        raise
