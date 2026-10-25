from fabriclib.common.errors import ValidationError


def read_options(args, names, flags=()):
    """Purpose: the `--name value` options and bare `--flag`s after a `fabricctl domain` command's words.
    Inputs:  args — list of str; names — the options that take a value; flags — the options that take none.
    Returns: dict {name: value, flag: True}.
    Fails:   ValidationError for an unknown option, a missing value or a stray word.
    Feeds:   domain/run_person_command, run_group_command, run_ou_command, run_machine_command,
             run_kerberos_command."""
    out, i = {}, 0
    while i < len(args):
        opt = args[i]
        if opt in flags:
            out[opt], i = True, i + 1
            continue
        if opt not in names:
            raise ValidationError(f"unknown option {opt}")
        if i + 1 >= len(args):
            raise ValidationError(f"{opt} needs a value")
        out[opt], i = args[i + 1], i + 2
    return out
