"""`fabricctl ipam`'s arguments (manual 1.10.4.16): the flags it knows, and the readers of their values."""
from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.fields import KEEP

FLAGS = {"--site", "--name", "--subnet", "--gateway", "--purpose", "--notes", "--access", "--dhcp", "--relay",
         "--allow-overlap", "--kind", "--mac", "--owner", "--dns", "--vlan", "--to-location"}
BARE = {"--no-subnet", "--no-split", "--force", "--no-apply", "--no-ask"}


def parse_args(args):
    """Purpose: split command arguments into positionals, --flag values (the last one counts) and bare flags.
    Inputs:  args — list of str.
    Returns: (positionals, {flag: value}, set of bare flags).
    Fails:   ValidationError for a value flag without a value, or a flag `fabricctl ipam` does not know.
    Feeds:   ipam/run_ipam_command."""
    pos, vals, bare, i = [], {}, set(), 0
    while i < len(args):
        a = args[i]
        if a in FLAGS:
            if i + 1 >= len(args):
                raise ValidationError(f"{a} needs a value")
            vals[a] = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            if a not in BARE:
                raise ValidationError(f"unknown option {a}")
            bare.add(a)
        else:
            pos.append(a)
        i += 1
    return pos, vals, bare


def on_off(text, flag):
    """Purpose: an on|off flag's value.
    Inputs:  text — str; flag — its name, for the message.
    Returns: bool.
    Fails:   ValidationError for anything but on or off.
    Feeds:   run_plan_change."""
    if str(text).lower() not in ("on", "off"):
        raise ValidationError(f"{flag} is on or off")
    return str(text).lower() == "on"


def keep(vals, flag, clear=False, convert=None):
    """Purpose: a set command's value: KEEP when the flag is absent; "" for "none" where it clears the field.
    Inputs:  vals — parsed flags; flag — e.g. "--gateway"; clear — whether "none" clears it; convert — function for
             the value (e.g. on/off), or None.
    Returns: KEEP, "" or the value.
    Fails:   what convert raises.
    Feeds:   run_plan_change (vlan set, subnet set, address set)."""
    if flag not in vals:
        return KEEP
    if clear and vals[flag].lower() == "none":
        return ""
    return convert(vals[flag], flag) if convert else vals[flag]
