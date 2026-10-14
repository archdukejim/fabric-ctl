import sys

from fabriclib.common.ask import ask


def confirm_plan(lines, word, yes=False, show=print, tty=None):
    """Purpose: show what a federation command will change, then have the person type a word to go on (decisions
             2.1.9.23, 2.1.6.58): "yes" for a DC type change, the site's name for a lost read-only DC.
    Inputs:  lines — what will be done, in order; word — what must be typed exactly (the question's ID is
             "federation.confirm" for both); yes — the command's --yes (consent given, nothing asked; never
             accepted where the caller requires typing); show — callable(str); tty — whether stdin is a terminal
             (default: asked).
    Returns: bool, whether the person agreed (False: nothing is to change).
    Fails:   never: no terminal and no --yes is a refusal (False), said so.
    Feeds:   run_federation_command (dc-type accept, rodc-lost)."""
    show("This will:")
    for n, line in enumerate(lines, 1):
        show(f"  {n}. {line}")
    if yes:
        return True
    if not (sys.stdin.isatty() if tty is None else tty):
        show("no terminal to confirm on, and no --yes: nothing was changed")
        return False
    return ask("federation.confirm", f"Type {word} to go on (anything else stops): ") == word
