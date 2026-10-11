import re

from fabriclib.common.errors import ValidationError
from fabriclib.directory.common.check_host_group_name import check_host_group_name

RULE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
PERSON_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.$-](?:[A-Za-z0-9 _.$-]{0,62}[A-Za-z0-9_.$-])?$")
# an absolute path, then its arguments: printable characters only (no newline, no control character)
COMMAND_RE = re.compile(r"^/[\x21-\x7e]*( [\x20-\x7e]*)?$")


def _who(value, field):
    """Purpose: one sudoUser or sudoRunAsUser value: ALL, a user name, or %group.
    Inputs:  value — str; field — the field's name, for the message.
    Returns: the value, stripped.
    Fails:   ValidationError "<field>: … is not a user name, %group or ALL".
    Feeds:   check_sudo_rule."""
    value = value.strip()
    if value == "ALL" or (value.startswith("%") and GROUP_RE.fullmatch(value[1:])) or PERSON_RE.fullmatch(value):
        return value
    raise ValidationError(f"{field}: {value!r} is not a user name, %group or ALL")


def check_sudo_rule(v, name, users, commands, run_as=None, hosts=None):
    """Purpose: a sudo rule's fields checked and made plain (manual 1.6.11.7): who (people and %groups), which commands
             (absolute paths, with their arguments, or ALL), as whom (default root), where (a host group, or ALL:
             every machine of the site). A value that passes is safe as an LDAP value; whether the people, groups and
             host group exist, and the ALL-to-everyone refusal, are the directory's checks (they need the domain).
    Inputs:  v — fabric vars (site_name); name — the rule's name; users, commands — lists of str; run_as — list of
             str or None (root); hosts — a host group's name (short or AD), or "ALL", "" or None (every machine).
    Returns: {"name", "users", "commands", "run_as", "hosts" ("ALL" or the host group's AD name)}.
    Fails:   ValidationError naming the field: a bad rule name, a value that is not a list of text, nobody, no
             command, a command that is not an absolute path or ALL, a bad user or group name, a bad host group.
    Feeds:   add_sudo_rule."""
    if not isinstance(name, str) or not RULE_RE.fullmatch(name):
        raise ValidationError("rule name: 1-63 characters, a-z 0-9, dashes and underscores, starting with a letter "
                              "or digit")
    for field, values in (("who", users), ("commands", commands), ("as", run_as)):
        if values is not None and (not isinstance(values, list) or not all(isinstance(x, str) for x in values)):
            raise ValidationError(f"{field}: a list of names")
    users = [_who(u, "who") for u in users or [] if u.strip()]
    if not users:
        raise ValidationError("who: at least one person or %group")
    commands = [c.strip() for c in commands or [] if c.strip()]
    if not commands:
        raise ValidationError("commands: at least one, an absolute path (with its arguments) or ALL")
    for c in commands:
        if c != "ALL" and (len(c) > 255 or not COMMAND_RE.fullmatch(c)):
            raise ValidationError(f"commands: {c!r} is not an absolute path (with its arguments) or ALL")
    run_as = [_who(r, "as") for r in run_as or [] if r.strip()] or ["root"]
    where = "ALL" if hosts in (None, "", "ALL") else f"{v['site_name']}-hosts-{check_host_group_name(v, hosts)}"
    return {"name": name, "users": users, "commands": commands, "run_as": run_as, "hosts": where}
