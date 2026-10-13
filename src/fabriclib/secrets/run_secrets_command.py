import sys

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import SECRETS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.secrets.load_secrets import load_secrets

USAGE = """usage: fabricctl secrets list                     the names of fabric's own secrets
       fabricctl secrets show <name>              one secret's value (audited, the name only)"""


def _flat(secrets):
    """Purpose: Flatten fabric's secrets for listing: each tsig_secrets entry becomes "tsig/<name>".
    Inputs:  secrets — the secrets dict.
    Returns: new dict; every other top-level key kept as is (radius_secrets stays one entry holding all
             RADIUS client secrets).
    Fails:   AttributeError if tsig_secrets is present but not a dict.
    Feeds:   run_secrets_command.
    """
    out = {k: v for k, v in secrets.items() if k != "tsig_secrets"}
    out.update({f"tsig/{k}": v for k, v in (secrets.get("tsig_secrets") or {}).items()})
    return out


def run_secrets_command(argv, path=SECRETS_FILE):
    """Purpose: `fabricctl secrets list` (names only) and `fabricctl secrets show <name>` (one value, e.g.
             keycloak_admin_password or tsig/npm), read from wherever fabric's secrets live.
    Inputs:  argv — ["list"] or ["show", name]; path — the secrets file, default SECRETS_FILE.
    Returns: exit status: 0 done (output on stdout), 1 error (message on stderr: OpenBao unavailable,
             unknown name), 2 usage.
    Fails:   load_secrets' ValidationError is reported, not raised; OSError from write_audit propagates;
             yaml.YAMLError for a malformed file.
    Feeds:   fabriclib/cli.py (fabricctl secrets).
    Notes:   every `show` is audited as SECRET_READ with the name, never the value.
    """
    if argv[:1] == ["list"] and len(argv) == 1:
        try:
            names = sorted(_flat(load_secrets(path)))
        except ValidationError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print("\n".join(names) if names else "no secrets")
        return 0
    if argv[:1] == ["show"] and len(argv) == 2:
        try:
            flat = _flat(load_secrets(path))
        except ValidationError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if argv[1] not in flat:
            print(f"error: no secret named {argv[1]!r} (fabricctl secrets list)", file=sys.stderr)
            return 1
        write_audit("root", "SECRET_READ", f"name={argv[1]}", "cli")
        print(flat[argv[1]])
        return 0
    print(USAGE, file=sys.stderr)
    return 2
