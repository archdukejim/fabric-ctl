from fabriclib.common.errors import ValidationError


def read_changes(args):
    """Purpose: the settings a whole restore or a reinstall changes (manual 1.3.7.7), from `--set key=value` words.
    Inputs:  args — the command's arguments.
    Returns: {key: value}, {} when none is given.
    Fails:   ValidationError for a --set without key=value.
    Feeds:   run_restore_command, run_reinstall_command (check_changes then checks them)."""
    changes = {}
    for i, a in enumerate(args):
        if a == "--set":
            key, sep, value = (args[i + 1] if i + 1 < len(args) else "").partition("=")
            if not sep:
                raise ValidationError("--set takes key=value, for example --set host_ip=10.0.5.2")
            changes[key] = value
    return changes
