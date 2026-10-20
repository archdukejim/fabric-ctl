import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.constants import MACHINE_TYPES
from fabriclib.directory.people_password import people_password
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


def add_machine(v, actor, name, source="cli", secrets=None, container="samba", type=None, managed=True,
                server=None, in_site=True):
    """Purpose: pre-create a machine (manual 1.6.7.3, S6.2; 1.6.13.3) with a one-time join password: the machine
             joins with `join-linux.sh --one-time`, so no admin password is typed on it. With a type it goes in that
             type's OU under OU=machines (OU=servers, OU=desktops, OU=network) and its group (`machines-servers`,
             ...), without one in OU=machines itself; in this site's group `site-<site>`; in `fabric-managed` unless
             unmanaged.
    Inputs:  v — fabric vars (site_name, ad_password_policy); actor — str, for the audit; name — 1-15 lower-case
             letters, digits, dashes; source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container (tests name their own); type — "server", "desktop", "network" or None;
             managed — False: not managed by fabric (manual 1.6.11.6); server — None, or the writable DC to make it
             at (a read-only DC's site, 2.1.6.52); in_site — False leaves it out of the site's group (the fabric
             host's own account: it is in dc-hosts instead, 1.6.13.6).
    Returns: the one-time join password: shown once, stored nowhere.
    Fails:   ValidationError "machine name: …", "type: …", "that name is already taken", the directory's refusals
             (run_op), load_secrets' errors.
    Feeds:   samba/run_domain_command (`fabricctl domain add-machine`); the web UI's domain section (S7).
    Notes:   audited as MACHINE_CREATE."""
    if not NAME_RE.match(name or ""):
        raise ValidationError("machine name: 1-15 characters, a-z 0-9 and dashes, not starting or ending with a dash")
    if type is not None and type not in MACHINE_TYPES:
        raise ValidationError(f"type: one of {', '.join(MACHINE_TYPES)} (its OU and group), not {type!r}")
    password = people_password(v)          # a one-time password the domain's policy accepts
    run_op(v, secrets if secrets is not None else load_secrets(), "create_machine",
           {"name": name, "password": password, "managed": bool(managed), "in_site": bool(in_site),
            **({"type": type} if type else {})}, container, server)
    write_audit(actor, "MACHINE_CREATE", f"machine={name}" + (f" type={type}" if type else "")
                + ("" if managed else " unmanaged"), source)
    return password
