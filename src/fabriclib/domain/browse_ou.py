from fabriclib.common.errors import ValidationError
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def browse_ou(v, ou="", q="", whole=False, internal=False, secrets=None, container="samba"):
    """Purpose: the directory browser's read (manual 1.8.8.4): the tree opened to one OU, its contents or a search,
             as the DC's browse_ou answers it (one level at a time).
    Inputs:  v — rendered vars; ou — the OU's path ("" for the domain); q — text to find; whole — bool, search the
             whole domain; internal — bool, show the grants' computed groups (1.8.8.3); secrets — fabric's secrets
             (default: load_secrets()); container — the DC's container.
    Returns: the DC's {"ou", "levels", "contents", "found", "kinds"}.
    Fails:   ValidationError: ou or q not text, the q longer than 64; the DC's ("no OU …", a whole-domain search
             without 2 characters, the DC not reachable).
    Feeds:   agent route GET /v1/directory/tree/…."""
    if not isinstance(ou, str) or not isinstance(q, str) or len(q) > 64:
        raise ValidationError("ou and q: text, q at most 64 characters")
    return run_op(v, secrets if secrets is not None else load_secrets(), "browse_ou",
                  {"ou": ou, "q": q, "whole": bool(whole), "internal": bool(internal)}, container)
