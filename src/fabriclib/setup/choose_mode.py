import os

from fabriclib.common.ask import ask
from fabriclib.common.console import BOLD, NC, YELLOW


def choose_mode(ctx):
    """Purpose: setup's start on a new install (manual 1.2.9.11.1, decision 2.1.2.19): [G]uided — the questions fabric
             needs, one at a time — or [A]dvanced — a menu of every setting — or [Q]uit.
    Inputs:  ctx — SetupContext: vars_file (an existing install has one), non_interactive, assume_yes. Interactive
             only on a new install with someone there.
    Returns: "guided" or "advanced"; "guided" without asking for an upgrade or a re-run (the settings exist: straight
             to the plan), an unattended run, or --yes. An answer that is not g, a or q is refused, saying which, and
             asked again.
    Fails:   SystemExit("setup cancelled") on Quit; EOFError from input().
    Feeds:   setup/run_setup (full runs, before collect_vars)."""
    if os.path.exists(ctx.vars_file) or ctx.non_interactive or ctx.assume_yes:
        return "guided"
    print(f"\n  {BOLD}[G]uided{NC}   - the questions fabric needs, one at a time (recommended)")
    print("  [A]dvanced - a menu of every setting")
    print("  [Q]uit")
    while True:
        answer = ask("setup.mode", "\n  Guided, Advanced or Quit? [G/a/q] ", "g").lower()
        if answer in ("g", "guided"):
            return "guided"
        if answer in ("a", "advanced"):
            return "advanced"
        if answer in ("q", "quit"):
            raise SystemExit("setup cancelled")
        print(f"    {YELLOW}{answer!r}: answer g (guided), a (advanced) or q (quit){NC}")
