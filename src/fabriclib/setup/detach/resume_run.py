import os

import yaml

from fabriclib.common.console import heading, info
from fabriclib.setup.ask_first_admin import ask_first_admin
from fabriclib.setup.detach.hand_over import hand_over
from fabriclib.setup.read_join_invitation import read_join_invitation


def resume_run(ctx, steps, last, remaining, join=None, hand=hand_over):
    """Purpose: run the last setup again from the first step that did not finish (decision 2.1.2.26, manual
             1.3.2.3.3), without its questions: only a secret it held in memory is asked again, when a step still
             ahead needs it.
    Inputs:  ctx — SetupContext from this command's options (non_interactive and admin_password_file are used to
             ask; the rest comes from the record); steps — STEPS; last — the last run's record (read_run): done,
             current, state, options; remaining — the steps not done (choose_start); join — this command's --join
             value (None: a bare prompt when the join step is ahead); hand — hand_over (tests give their own).
    Returns: hand_over's exit status for a new run with the same options and done list. Asked first: the join
             invitation (read_join_invitation) when the last run joined and its join step is ahead; the first admin's
             password (ask_first_admin, needed=True) when the last run had one and the admin step is ahead.
    Fails:   SetupError from read_join_invitation or ask_first_admin (unattended without the file, a refused
             password); OSError / yaml errors reading the settings; whatever hand_over raises.
    Feeds:   setup/run_setup."""
    opts = dict(last.get("options") or {})
    heading("fabric setup")
    info(f"the last setup did not finish (it stopped at [{last.get('current') or remaining[0]}]): resuming from "
         f"[{remaining[0]}] without the questions (sudo fabricctl setup --restart asks them again)")
    ctx.offline, ctx.assume_yes = bool(opts.get("offline")), bool(opts.get("assume_yes"))
    if not ctx.admin_password_file and opts.get("admin_password_file"):
        ctx.admin_password_file = opts["admin_password_file"]
    opts["admin_password_file"] = ctx.admin_password_file
    if "deploy" in remaining:
        with open(os.path.join(ctx.config_dir, "fabric.yaml")) as f:
            ctx.vars = yaml.safe_load(f) or {}
    else:
        ctx.load_state()
    if "join" in remaining and opts.get("join"):
        ctx.join_invitation = read_join_invitation(join if join is not None else "", ctx.non_interactive)
    if "admin" in remaining and opts.get("admin_password"):
        ask_first_admin(ctx, needed=True)
    record = {"done": list(last.get("done") or []), "restart_services": list(last.get("restart_services") or []),
              "options": opts}
    ctx.restart_services = set(record["restart_services"])
    return hand(ctx, steps, record)
