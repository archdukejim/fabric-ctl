import datetime
import glob
import os
import secrets as token
from functools import partial

import yaml

from fabriclib.common.console import info, warn
from fabriclib.setup.detach.can_detach import can_detach
from fabriclib.setup.detach.constants import HANDOFF_DIR, HANDOFF_SUFFIX, LOG
from fabriclib.setup.detach.follow_run import follow_run
from fabriclib.setup.detach.launch_worker import launch_worker
from fabriclib.setup.detach.write_handoff import write_handoff
from fabriclib.setup.detach.write_run import write_run
from fabriclib.setup.run_steps import run_steps


def _fresh_log(config_dir):
    """Purpose: an empty log for the new run, the previous run's kept as setup-run.log.1.
    Inputs:  config_dir — the install's config folder.
    Returns: the log's path (str), an empty 0600 file.
    Fails:   OSError.
    Feeds:   hand_over."""
    path = os.path.join(config_dir, LOG)
    if os.path.exists(path):
        os.replace(path, f"{path}.1")
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600))
    os.chmod(path, 0o600)
    return path


def hand_over(ctx, steps, record, launch=launch_worker, follow=follow_run, detach=can_detach,
              handoff_dir=HANDOFF_DIR):
    """Purpose: after setup's last question, give its work to fabric-setup.service and follow it (decision 2.1.2.26,
             manual 1.3.2.3): the settings saved, the secrets typed in the questions handed over in a root-only file,
             the run recorded, the unit started, its log shown until it ends.
    Inputs:  ctx — SetupContext with the answers (vars; admin_password and join_invitation in memory); steps —
             STEPS; record — the new run's record: done (the steps already done, for a resumed run), options
             (offline, assume_yes, guided, join, admin_password_file); launch, follow, detach — launch_worker,
             follow_run, can_detach (tests give their own); handoff_dir — where the hand-off file goes.
    Returns: the run's exit status (follow_run's: 0, 1, 130); on a host not booted with systemd, said so, the steps
             run here (run_steps) with the same record. The record gets a new id, state "running", the hand-off
             file's path (None without secrets), started; the previous run's hand-off file, if one was left, is
             removed. While deploy is ahead, ctx.vars is saved to fabric.yaml first (the unit reads its settings from
             it, as deploy does).
    Fails:   SetupError from launch (the unit could not start: the hand-off file removed, the record marked
             failed); OSError writing the files.
    Feeds:   setup/run_setup (after the plan), detach/resume_run."""
    config_dir = ctx.config_dir
    os.makedirs(config_dir, mode=0o750, exist_ok=True)
    save = partial(write_run, config_dir)
    record.update(id=datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + token.token_hex(3), state="running",
                  current=None, result=None, finished=None, handoff=None,
                  started=datetime.datetime.now().astimezone().isoformat(timespec="seconds"))
    record.setdefault("done", [])
    record.setdefault("restart_services", sorted(ctx.restart_services))
    selected = [name for name, _, _ in steps if name not in record["done"]]
    if "deploy" in selected:
        path = os.path.join(config_dir, "fabric.yaml")
        with open(path, "w") as f:
            yaml.safe_dump(ctx.vars, f, sort_keys=False)
        os.chmod(path, 0o640)
    for stale in glob.glob(os.path.join(handoff_dir, f"setup-*{HANDOFF_SUFFIX}")):
        os.remove(stale)                    # a run that never read its secrets
    if not detach():
        warn("this host was not booted with systemd: setup's work runs in this session (a dropped connection stops "
             "it; `sudo fabricctl setup` then resumes)")
        save(record)
        return run_steps(ctx, steps, selected, guided=bool(record["options"].get("guided")), record=record,
                         save=save)
    handed = {k: v for k, v in (("admin_password", ctx.admin_password), ("join_invitation", ctx.join_invitation))
              if v}
    log = _fresh_log(config_dir)
    record["handoff"] = write_handoff(record["id"], handed, handoff_dir) if handed else None
    save(record)
    try:
        launch(record["id"], ctx.deploy_base, log)
    except BaseException:
        if record["handoff"] and os.path.exists(record["handoff"]):
            os.remove(record["handoff"])
        record.update(handoff=None, state="failed", result=1)
        save(record)
        raise
    info("setup's work runs as fabric-setup.service: a dropped connection does not stop it\n"
         "    Ctrl-C stops following, not the work; sudo fabricctl setup follows it again")
    return follow(config_dir)
