import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.federation.constants import DC_TYPE_PREFIX


def read_change_token(value, stdin=None, tty=None):
    """Purpose: the DC type change token for `fabricctl federation dc-type accept` (decision 2.1.9.23), never taken
             from the command line: it carries a one-time secret, and argv is readable by every user on the host.
    Inputs:  value — what followed accept: "" (none: a hidden prompt, or stdin when it is not a terminal), "-"
             (stdin), "@<path>" (a file); stdin — a file object (default sys.stdin); tty — whether stdin is a terminal
             (default: asked).
    Returns: the token text, stripped.
    Fails:   ValidationError: the token itself given on the command line; "cannot read the token from <path>: …";
             "no change token given" (empty input).
    Feeds:   run_federation_command (dc-type accept)."""
    stdin = stdin or sys.stdin
    tty = stdin.isatty() if tty is None else tty
    value = value or ""
    if value.startswith(DC_TYPE_PREFIX):
        raise ValidationError("do not put the change token on the command line (every user on this host can read "
                              "it): paste it at the prompt, or use @FILE or - (stdin)")
    if value.startswith("@"):
        try:
            with open(value[1:]) as f:
                text = f.read()
        except OSError as e:
            raise ValidationError(f"cannot read the token from {value[1:]}: {e.strerror}") from None
    elif value == "-" or not tty:
        text = stdin.read()
    elif value:
        raise ValidationError(f"{value!r}: give the token as @FILE, - (stdin) or at the prompt")
    else:
        text = ask_secret("federation.dc_type_token", "Change token (from the site above; hidden): ")
    if not text.strip():
        raise ValidationError("no change token given")
    return text.strip()
