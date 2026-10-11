import re

from fabriclib.common.errors import ValidationError
from fabriclib.samba.logon_ou_path import logon_ou_path

# a group's sAMAccountName as fabric lets it be named: no character AD refuses ("/\[]:;|=,+*?<>@), no leading or
# trailing space ("Domain Admins" is fine)
_GROUP = re.compile(r"^[A-Za-z0-9_.$-](?:[A-Za-z0-9 _.$-]{0,62}[A-Za-z0-9_.$-])?$")
RIGHTS = ("console", "remote")
MACHINES = ("", "machines")             # an OU covering every machine of the site


def _groups(ou, right, value):
    """Purpose: one right's list of groups, checked and without repeats.
    Inputs:  ou — the OU's path (for messages); right — "console" or "remote"; value — list of str (or None).
    Returns: list of str, in the order given.
    Fails:   ValidationError for a value that is not a list, or a name AD could not hold.
    Feeds:   check_logon_policies."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError(f"logon_policies.{ou or 'site'}.{right}: a list of group names")
    out = []
    for name in value:
        name = str(name).strip() if isinstance(name, str) else name
        if not isinstance(name, str) or not _GROUP.match(name):
            raise ValidationError(f"logon_policies.{ou or 'site'}.{right}: {name!r} is not a group name (letters, "
                                  "digits, spaces inside, . - _ $; at most 64)")
        if name.lower() not in (n.lower() for n in out):
            out.append(name)
    return out


def check_logon_policies(value):
    """Purpose: the setting `logon_policies` (manual 1.6.11.4) checked and normalised, before anything is rendered or
             saved: null (the site's log-on rights as before 0.9, 2.1.6.44), or a map from an OU's path below the
             site's OU to {"console": [groups], "remote": [groups]}. The site's machines must stay covered: the map
             names the site's OU ("") or its OU=machines, and those may not grant nobody (only break-glass could sign
             in). Whether the groups exist is checked by the editor in the domain, not here.
    Inputs:  value — None or dict.
    Returns: None, or {ou path: {"console": [...], "remote": [...]}} with the paths normalised (logon_ou_path).
    Fails:   ValidationError naming the first problem: not a map, an OU path or a group name refused, an unknown
             key, the same OU twice, no policy on the site's OU or OU=machines, or one of those granting nobody.
    Feeds:   deploy/check_settings (every apply), samba/converge_domain, set_logon_policy, clear_logon_policy."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("logon_policies: a map of OU path to {console: [groups], remote: [groups]}, or null")
    out = {}
    for key, entry in value.items():
        ou = logon_ou_path(key)
        if ou in out:
            raise ValidationError(f"logon_policies: the OU {ou or 'site'} is named twice")
        if not isinstance(entry, dict) or set(entry) - set(RIGHTS):
            raise ValidationError(f"logon_policies.{ou or 'site'}: only console and remote, each a list of groups")
        out[ou] = {r: _groups(ou, r, entry.get(r)) for r in RIGHTS}
    if not any(ou in out for ou in MACHINES):
        raise ValidationError("logon_policies: no policy on the site's OU or its OU=machines, so its machines would "
                              "have no log-on policy of fabric's: keep one there")
    for ou in MACHINES:
        if ou in out and not (out[ou]["console"] or out[ou]["remote"]):
            raise ValidationError(f"logon_policies.{ou or 'site'}: grants nobody, so only break-glass could sign in "
                                  "to the site's machines: name at least one group")
    return dict(sorted(out.items()))
