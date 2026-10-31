#!/usr/bin/env python3
"""fabricctl setup — install or re-converge fabric on this host.

  sudo fabricctl setup                      interactive
  sudo fabricctl setup --file vars.yaml     answers from a file (asks only for what is missing)
  sudo fabricctl setup --file vars.yaml --non-interactive --yes --approve all   fully unattended
  sudo fabricctl setup --step certs         run one step (see --list)
  sudo fabricctl setup --undo firewall      undo one kind of host change and record it as declined
  sudo fabricctl setup --restart            start over with the questions though the last run did not finish
  sudo fabricctl doctor                     run only the end-to-end checks
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from fabriclib.common.console import err, heading, info  # noqa: E402
from fabriclib.consent.ask_consent import ask_consent  # noqa: E402
from fabriclib.consent.initial_host_choices import initial_host_choices  # noqa: E402
from fabriclib.consent.plan_host_changes import plan_host_changes  # noqa: E402
from fabriclib.consent.planned_vars import planned_vars  # noqa: E402
from fabriclib.setup.advanced.setup_menu import setup_menu  # noqa: E402
from fabriclib.setup.apply_plan_defaults import apply_plan_defaults  # noqa: E402
from fabriclib.setup.ask_first_admin import ask_first_admin  # noqa: E402
from fabriclib.setup.choose_mode import choose_mode  # noqa: E402
from fabriclib.setup.choose_plan import choose_plan  # noqa: E402
from fabriclib.setup.collect_vars import collect_vars  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.choose_start import choose_start  # noqa: E402
from fabriclib.setup.detach.follow_run import follow_run  # noqa: E402
from fabriclib.setup.detach.hand_over import hand_over  # noqa: E402
from fabriclib.setup.detach.read_run import read_run  # noqa: E402
from fabriclib.setup.detach.resume_run import resume_run  # noqa: E402
from fabriclib.setup.detach.run_worker import run_worker  # noqa: E402
from fabriclib.setup.detach.unit_running import unit_running  # noqa: E402
from fabriclib.setup.errors import SetupError  # noqa: E402
from fabriclib.setup.finish_vars import finish_vars  # noqa: E402
from fabriclib.setup.read_join_invitation import read_join_invitation  # noqa: E402
from fabriclib.setup.require_terminal import require_terminal  # noqa: E402
from fabriclib.setup.run_steps import run_steps  # noqa: E402
from fabriclib.setup.steps import STEPS  # noqa: E402
from fabriclib.setup.verify_install import run as verify  # noqa: E402
from fabriclib.security.ufw_active import ufw_active  # noqa: E402
from fabriclib.undo.undo_group import undo_group  # noqa: E402

NEEDS_INPUT = {"preflight", "host", "docker", "join", "deploy"}   # before the rendered vars exist


def main(argv=None):
    """Purpose: `fabricctl setup` / `fabricctl doctor`: parse options, collect settings, show the plan and run
             the selected steps of STEPS in order.
    Inputs:  argv — option list (None: sys.argv[1:]): --file, --deploy-base (default /opt), --offline,
             --non-interactive, --yes/-y, --approve GROUPS / --decline GROUPS (host changes, repeatable),
             --step NAME (repeatable), --join [@FILE|-] (join an upstream fabric; read_join_invitation),
             --undo GROUP (undo/undo_group: revert one host change, nothing else runs), --list, --restart, --doctor
             (hidden, used by doctor), --worker RUN (hidden: the unit's own command, detach/run_worker).
    Returns: exit status: 0 done (or --list printed), 1 a SetupError (message printed), 130 interrupted (or, while
             following the unit, detached). A full run (no --step) asks its questions here and hands the steps to
             fabric-setup.service, following its log (detach/hand_over; decision 2.1.2.26): while that unit runs,
             setup only re-attaches to it; when the last run did not finish, it resumes from the first step that
             did not (detach/resume_run), unless --restart, --file or --join start over. The steps before deploy
             (preflight, host, docker, deploy) collect vars first, and the plan is shown only when no --step is
             given; --step runs stay in this session. A new install with
             someone there starts with [G]uided / [A]dvanced (choose_mode; Advanced: the menu of every setting,
             1.2.9.11); the plan's [P]roceed is the one yes for every host change it lists (2.1.2.18). Without a
             plan (--step, --yes), the changes that need an answer are listed with one question; unattended,
             --approve / --decline answer (--yes approves none).
    Fails:   SystemExit(2) from argparse on bad options; SystemExit("setup cancelled") when Quit is chosen at the
             start, in the menu or in the plan; any exception other than SetupError/KeyboardInterrupt from a step
             (CalledProcessError, CommandError, ValidationError, OSError) propagates as a traceback.
    Feeds:   cli main (`setup`, `doctor`) and this file's `__main__`."""
    ap = argparse.ArgumentParser(prog="fabricctl setup", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", help="vars file (fabric.yaml / custom-vars.yaml)")
    ap.add_argument("--deploy-base", default="/opt", help="install root (default /opt)")
    ap.add_argument("--offline", action="store_true", help="never download; images and packages must be present")
    ap.add_argument("--non-interactive", action="store_true", help="never prompt; fail on missing values")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="accept the plan without the Proceed prompt (approves no host change: see --approve)")
    ap.add_argument("--approve", action="append", metavar="GROUPS",
                    help="allow these host changes without asking: packages, runtime, services, accounts, resolver, "
                         "ports, firewall, own_rules (removes the host's own ufw rules), trust, time, member "
                         "(comma-separated, repeatable) or all")
    ap.add_argument("--decline", action="append", metavar="GROUPS",
                    help="refuse these host changes (recommended ones are then left unmanaged and shown in status); "
                         "--decline own_rules keeps the host's own ufw rules")
    ap.add_argument("--step", action="append", help="run only this step (repeatable)")
    ap.add_argument("--admin-password-file", metavar="FILE",
                    help="the first admin's password, read from FILE (unattended; never on the command line)")
    ap.add_argument("--undo", metavar="GROUP",
                    help="undo one kind of host change fabric made (runtime, firewall, trust, time, resolver, "
                         "member) and record it as declined; nothing else runs")
    ap.add_argument("--join", metavar="@FILE", nargs="?", const="",
                    help="join an upstream fabric as a new site (a fresh install): paste the invitation from "
                         "`fabricctl federation invite` at the prompt, or give @FILE or - (stdin)")
    ap.add_argument("--list", action="store_true", help="list the steps and exit")
    ap.add_argument("--restart", action="store_true",
                    help="start over with the questions and every step, though the last run did not finish")
    ap.add_argument("--doctor", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--worker", metavar="RUN", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.list:
        for name, _, desc in STEPS:
            print(f"  {name:10} {desc}")
        return 0
    if args.worker:                            # inside fabric-setup.service (2.1.2.26)
        return run_worker(args.worker, args.deploy_base, STEPS)

    if args.step is None and not (args.undo or args.doctor):
        ctx = SetupContext(deploy_base=args.deploy_base, non_interactive=args.non_interactive,
                           admin_password_file=args.admin_password_file)
        last = read_run(ctx.config_dir)
        what, remaining = choose_start(unit_running(), last, [n for n, _, _ in STEPS],
                                       start_over=bool(args.restart or args.file or args.join is not None))
        try:
            if what == "attach":
                info("a setup is already running (fabric-setup.service): following it; no questions are asked "
                     "and options given now are not used")
                return follow_run(ctx.config_dir)
            if what == "resume":
                return resume_run(ctx, STEPS, last, remaining, args.join)
        except SetupError as e:
            err(str(e))
            return 1
        except KeyboardInterrupt:
            err("interrupted")
            return 130

    try:
        # a run that asks (not doctor, an undo, or steps that need no input) needs someone at a terminal (2.1.3.4)
        if not (args.doctor or args.undo) and (args.step is None or any(s in NEEDS_INPUT for s in args.step)):
            require_terminal(args.non_interactive)
        invitation = read_join_invitation(args.join, args.non_interactive)
    except SetupError as e:
        err(str(e))
        return 1
    ctx = SetupContext(deploy_base=args.deploy_base, user_vars_file=args.file, offline=args.offline,
                       non_interactive=args.non_interactive, assume_yes=args.yes, join_invitation=invitation,
                       admin_password_file=args.admin_password_file)
    try:
        if args.undo:
            ctx.load_state()
            undo_group(ctx, args.undo, interactive=not ctx.non_interactive, assume_yes=args.yes)
            return 0
        if args.doctor:
            ctx.load_state()
            heading("fabric doctor")
            verify(ctx)
            return 0

        selected = args.step or [name for name, _, _ in STEPS]
        unknown = set(selected) - {n for n, _, _ in STEPS}
        if unknown:
            raise SetupError(f"unknown step(s): {', '.join(sorted(unknown))} (see --list)")
        jinja = os.path.join(ctx.source_dir, "jinja")
        decided, mode = None, None
        if any(s in NEEDS_INPUT for s in selected):
            heading("fabric setup")
            mode = choose_mode(ctx) if args.step is None else "guided"
            collect_vars(ctx, ask=mode != "advanced")
            apply_plan_defaults(ctx)
            ctx.host_choices = initial_host_choices(ctx.config_dir, args.approve, args.decline)
            if mode == "advanced":             # every setting in one menu, the required ones first (2.1.2.19)
                setup_menu(ctx)
                finish_vars(ctx)
            ask_first_admin(ctx)
            if args.step is None:              # the plan: Proceed is the one yes for the host changes (2.1.2.18)
                def plan_host():
                    rendered = planned_vars(ctx)
                    return rendered, plan_host_changes(rendered, ctx.deploy_base, ctx.config_dir, jinja, selected)
                decided = choose_plan(ctx, plan_host)
        else:
            ctx.load_state()
        planned = planned_vars(ctx) if any(s in NEEDS_INPUT for s in selected) else ctx.vars
        answers = ask_consent(ctx.config_dir, plan_host_changes(planned, ctx.deploy_base, ctx.config_dir, jinja,
                                                                selected),
                              interactive=not ctx.non_interactive, approve=args.approve, decline=args.decline,
                              stops={"ports"} if ufw_active() else set(), decided=decided)
        # ufw already on blocks fabric's containers from the DC on this host unless fabric adds its rules (2.1.2.12):
        # said now, before any step changes the host, not when Keycloak cannot reach the DC much later
        if answers.get("ports") == "no" and "firewall" in selected and ufw_active():
            raise SetupError("ufw is on, and without fabric's firewall rules it blocks fabric's own containers from "
                             "this host's domain controller (Keycloak, FreeRADIUS): setup would fail later. fabric "
                             "only opens its own ports beside your rules: run setup again and allow the ports "
                             "fabric needs (or --approve ports)")

        if args.step is None:                  # the work goes to fabric-setup.service; this session follows it
            return hand_over(ctx, STEPS, {"options": {
                "offline": ctx.offline, "assume_yes": ctx.assume_yes, "guided": mode == "guided",
                "join": bool(ctx.join_invitation), "admin_password": bool(ctx.admin_password),
                "admin_password_file": ctx.admin_password_file}})
        return run_steps(ctx, STEPS, selected, guided=mode == "guided")
    except SetupError as e:
        err(str(e))
        return 1
    except KeyboardInterrupt:
        err("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
