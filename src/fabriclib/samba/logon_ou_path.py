import re

from fabriclib.common.errors import ValidationError

_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SITE_WORDS = ("", "site", "/")          # the site's OU itself, as a person may type it


def logon_ou_path(text):
    """Purpose: an OU's path below the site's OU as a log-on policy names it (manual 1.6.11.4): segments of letters,
             digits, dots, dashes and underscores, separated by "/", lower case (AD's names do not care); "", "site"
             or "/" for the site's OU itself, kept as "".
    Inputs:  text — str (or None).
    Returns: str, e.g. "machines/linux", or "".
    Fails:   ValidationError for a segment outside that rule, an empty segment, more than 8 levels, or "rights" (the
             name of the site's log-on GPO before per-OU policies).
    Feeds:   check_logon_policies, set_logon_policy, clear_logon_policy, logon_overview."""
    path = str(text or "").strip().lower()
    if path in SITE_WORDS:
        return ""
    segs = path.strip("/").split("/")
    if len(segs) > 8 or not all(_SEGMENT.match(s) for s in segs):
        raise ValidationError(f"OU {text!r}: a path below the site's OU such as machines or machines/linux (letters, "
                              "digits, . - _ in each part, at most 8 levels), or site for the site's OU itself")
    if segs == ["rights"]:
        raise ValidationError("OU rights: that name is the site's log-on GPO from before per-OU policies; "
                              "name the OU otherwise")
    return "/".join(segs)
