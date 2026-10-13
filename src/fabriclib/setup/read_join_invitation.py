import sys

from fabriclib.common.ask import ask_secret
from fabriclib.federation.constants import INVITE_PREFIX
from fabriclib.setup.errors import SetupError


def read_join_invitation(value, non_interactive=False):
    """Purpose: the invitation for `setup --join`, never taken from the command line: it carries a secret, and
             argv is readable by every user on the host.
    Inputs:  value — what followed --join: None (no --join), "" (bare --join: a hidden prompt, or stdin when it is
             not a terminal), "-" (stdin), "@<path>" (a file); non_interactive — never prompt.
    Returns: the invitation text (stripped), or None without --join.
    Fails:   SetupError "do not put the invitation on the command line ..." when the value is the invitation
             itself; "cannot read the invitation from <path>: ..."; "no invitation given" (empty input, or a
             terminal with --non-interactive).
    Feeds:   run_setup main (ctx.join_invitation)."""
    if value is None:
        return None
    if value.startswith(INVITE_PREFIX):
        raise SetupError("do not put the invitation on the command line (every user on this host can read it): "
                         "run `fabricctl setup --join` and paste it at the prompt, or use --join @FILE")
    if value.startswith("@"):
        try:
            with open(value[1:]) as f:
                text = f.read()
        except OSError as e:
            raise SetupError(f"cannot read the invitation from {value[1:]}: {e.strerror}") from None
    elif value == "-" or not sys.stdin.isatty():
        text = sys.stdin.read()
    elif non_interactive:
        raise SetupError("no invitation given: --join @FILE or on stdin with --non-interactive")
    else:
        text = ask_secret("setup.join_invitation", "Invitation (from fabricctl federation invite; hidden): ")
    if not text.strip():
        raise SetupError("no invitation given")
    return text.strip()
