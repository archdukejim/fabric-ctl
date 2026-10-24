import sys

from fabriclib.setup.errors import SetupError


def require_terminal(non_interactive, isatty=None):
    """Purpose: refuse a setup that would ask its questions where nobody can answer (decision 2.1.3.4): with no
             terminal on stdin (a pipe, `ssh -T`, a script), the first question (Guided or Advanced) used to end in a
             Python EOFError. Refused before anything is asked or changed, saying how to run it unattended.
    Inputs:  non_interactive — --non-interactive given (nothing is asked then); isatty — callable() -> bool
             (default sys.stdin.isatty; tests give their own).
    Returns: None when setup may ask (a terminal) or will not (--non-interactive).
    Fails:   SetupError naming --non-interactive and --file.
    Feeds:   setup/run_setup (a run that asks: not --doctor, --undo or a step that needs no input)."""
    if non_interactive or (isatty or sys.stdin.isatty)():
        return
    raise SetupError("setup asks its questions at a terminal, and there is none here (stdin is not a terminal). "
                     "Run it unattended instead: sudo fabricctl setup --non-interactive --file FILE, with your "
                     "answers in FILE (manual 3.3.1.1.2), or --non-interactive alone for the defaults. "
                     "Nothing was asked or changed.")
