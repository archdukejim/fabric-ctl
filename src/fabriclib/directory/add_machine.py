import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


OS_FAMILIES = ("linux", "windows")


def add_machine(v, actor, name, source="cli", secrets=None, container="samba", os=None, managed=True):
    """Purpose: pre-create a machine in this site's OU=machines (in OU=linux or OU=windows when its OS is given,
             1.6.11.5) with a one-time join password (manual 1.6.7.3, S6.2): the machine joins with
             `join-linux.sh --one-time`, so no admin password is typed on it.
    Inputs:  v — fabric vars (site_name, ad_password_policy); actor — str, for the audit; name — 1-15 lower-case
             letters, digits, dashes; source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container (tests name their own); os — "linux", "windows" or None; managed —
             False: not a fabric-machine (manual 1.6.11.6).
    Returns: the one-time join password: shown once, stored nowhere.
    Fails:   ValidationError "machine name: …", "os: …", "that name is already taken", the directory's refusals
             (run_op), load_secrets' errors.
    Feeds:   samba/run_domain_command (`fabricctl domain add-machine`); the web UI's domain section (S7).
    Notes:   audited as MACHINE_CREATE."""
    if not NAME_RE.match(name or ""):
        raise ValidationError("machine name: 1-15 characters, a-z 0-9 and dashes, not starting or ending with a dash")
    if os is not None and os not in OS_FAMILIES:
        raise ValidationError(f"os: one of {', '.join(OS_FAMILIES)} (the OU it goes in), not {os!r}")
    password = people_password(v)          # a one-time password the domain's policy accepts
    run_op(v, secrets if secrets is not None else load_secrets(), "create_machine",
           {"name": name, "password": password, "managed": bool(managed), **({"os": os} if os else {})},
           container)
    write_audit(actor, "MACHINE_CREATE", f"machine={name}" + (f" os={os}" if os else "")
                + ("" if managed else " unmanaged"), source)
    return password
