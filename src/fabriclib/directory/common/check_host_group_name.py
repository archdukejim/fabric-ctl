import re

from fabriclib.common.errors import ValidationError

HOST_GROUP_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$")


def check_host_group_name(v, name):
    """Purpose: a host group's short name (manual 1.6.11.7), given short (`web`) or as its AD name
             (`<site>-hosts-web`); a name that passes is safe in an LDAP filter and a DN.
    Inputs:  v — fabric vars (site_name); name — str.
    Returns: the short name.
    Fails:   ValidationError "host group: 1-32 characters, …".
    Feeds:   create_host_group, remove_host_group, set_host_group_member, common/check_sudo_rule."""
    prefix = f"{v['site_name']}-hosts-"
    name = name if isinstance(name, str) else ""
    short = name[len(prefix):] if name.startswith(prefix) else name
    if not HOST_GROUP_RE.fullmatch(short):
        raise ValidationError("host group: 1-32 characters, a-z 0-9 and dashes, not starting or ending with a dash "
                              f"(the group is {prefix}<name>)")
    return short
