import os
from functools import partial

import yaml

from fabriclib.common.console import err
from fabriclib.setup.context import SetupContext
from fabriclib.setup.detach.read_handoff import read_handoff
from fabriclib.setup.detach.read_run import read_run
from fabriclib.setup.detach.write_run import write_run
from fabriclib.setup.errors import SetupError
from fabriclib.setup.run_steps import run_steps


def run_worker(run_id, deploy_base, steps, read_secrets=read_handoff):
    """Purpose: `fabricctl setup --worker <run>` — setup's work inside fabric-setup.service (decision 2.1.2.26,
             manual 1.3.2.3): the recorded run's remaining steps, with the answers its questions saved and the
             secrets they handed over, its progress kept in the run record.
    Inputs:  run_id — the run to do (the unit's argument); deploy_base — the install root; steps — STEPS;
             read_secrets — read_handoff (tests give their own). Reads <config>/setup-run.yaml and, before deploy,
             <config>/fabric.yaml (the settings), after it vars.yaml.
    Returns: exit status from run_steps (0 done, 1 a step stopped it, 130 interrupted); 1 when the record is missing,
             names another run or has finished (said so, nothing run), or when the handed-over secrets are refused.
             There is no terminal: a step's question takes its unattended answer (ctx.non_interactive).
    Fails:   whatever run_steps lets through (a step's unexpected exception, the record marked failed); OSError /
             yaml errors reading the settings.
    Feeds:   setup/run_setup (--worker), started by detach/launch_worker."""
    ctx = SetupContext(deploy_base=deploy_base)
    record = read_run(ctx.config_dir)
    if not record or record.get("id") != run_id or record.get("state") != "running":
        err(f"setup run {run_id} is not the one recorded as running in {ctx.config_dir}: nothing to do")
        return 1
    save = partial(write_run, ctx.config_dir)
    secrets = {}
    if record.get("handoff"):
        try:
            secrets = read_secrets(record["handoff"])
        except SetupError as e:
            err(str(e))
            record.update(handoff=None, state="failed", result=1)
            save(record)
            return 1
        record["handoff"] = None
        save(record)
    opts = record.get("options") or {}
    ctx.offline, ctx.assume_yes, ctx.non_interactive = bool(opts.get("offline")), bool(opts.get("assume_yes")), True
    ctx.admin_password_file = opts.get("admin_password_file")
    ctx.admin_password = secrets.get("admin_password")
    ctx.join_invitation = secrets.get("join_invitation")
    ctx.restart_services = set(record.get("restart_services") or [])
    done = set(record.get("done") or [])
    selected = [name for name, _, _ in steps if name not in done]
    if "deploy" in selected:                  # the settings the questions saved (and the steps before deploy)
        with open(os.path.join(ctx.config_dir, "fabric.yaml")) as f:
            ctx.vars = yaml.safe_load(f) or {}
    else:
        ctx.load_state()
    return run_steps(ctx, steps, selected, guided=bool(opts.get("guided")), record=record, save=save)
