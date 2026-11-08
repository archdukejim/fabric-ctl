import os

from fabriclib.common.console import info
from fabriclib.setup.detach.can_detach import can_detach


def site_wanted(ctx, mode, terminal, detach=can_detach):
    """Purpose: whether this run's questions go to the browser (decision 2.1.8.46): Guided on a new install, with
             someone there. Advanced, unattended runs and upgrades stay in the terminal, and so does --terminal.
    Inputs:  ctx — SetupContext: vars_file, non_interactive, assume_yes; mode — "guided" or "advanced" (choose_mode);
             terminal — --terminal given; detach — can_detach (the site hands setup's work to the unit, 1.3.6.2).
    Returns: bool. A host not booted with systemd stays in the terminal, saying so.
    Fails:   never.
    Feeds:   setup/run_setup."""
    if mode != "guided" or terminal or ctx.non_interactive or ctx.assume_yes or os.path.exists(ctx.vars_file):
        return False
    if not detach():
        info("this host was not booted with systemd: Guided stays in the terminal")
        return False
    return True
