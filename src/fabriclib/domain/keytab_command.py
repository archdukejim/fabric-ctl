import re

from fabriclib.common.errors import ValidationError
from fabriclib.directory.list_machines import list_machines
from fabriclib.secrets.load_secrets import load_secrets

SERVICE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,31}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
OWN = {"host", "restrictedkrbhost", "cifs"}           # the machine's own names: in its /etc/krb5.keytab already


def keytab_command(v, name, service, user, path="", secrets=None, container="samba"):
    """Purpose: the one command a machine's administrator pastes into an SSH session on that machine to install a
             service's keytab (manual 1.6.12.9, Add a service): fabric never holds a key. The command runs the join
             kit's `fabric-keytab` with sudo, which uses the machine's own domain account to add the SPN to its own
             computer account and writes the keytab, owned by the user, 0600. Nothing secret is in it.
    Inputs:  v — rendered vars; name — the machine's host name (one of the domain's in OU=machines); service — a
             service class (HTTP, postgres, ...; not the machine's own host, RestrictedKrbHost or cifs); user — the
             service's local user; path — where the service reads its keytab, or "" (the tool's default,
             /etc/krb5-<class>.keytab); secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"machine", "command", "spns": [the two SPNs it adds]}.
    Fails:   ValidationError "service: …", "user: …", "path: …", "no machine <name> in the domain", "<name> is a
             fabric host …"; list_machines' (the DC not reachable).
    Feeds:   agent route POST /v1/machines/<name>/keytab; domain/run_machine_command (keytab).
    Notes:   it changes nothing, so it is not audited; the machine's own sudo policy (1.6.11) decides who may run it."""
    if not isinstance(service, str) or not SERVICE_RE.match(service) or service.lower() in OWN:
        raise ValidationError("service: a service class such as HTTP (not host, RestrictedKrbHost or cifs: the "
                              "machine's own)")
    if not isinstance(user, str) or not USER_RE.match(user):
        raise ValidationError("user: the service's local user name")
    if not isinstance(path, str) or (path and (not path.startswith("/") or path == "/etc/krb5.keytab"
                                               or not re.match(r"^/[A-Za-z0-9._/-]{1,200}$", path))):
        raise ValidationError("path: an absolute path other than /etc/krb5.keytab, or none")
    found = [m for m in list_machines(v, secrets if secrets is not None else load_secrets(), container)
             if m["name"] == str(name).lower()]
    if not found:
        raise ValidationError(f"no machine {name} in the domain")
    if ",ou=fabric-hosts," in found[0]["dn"].lower():
        raise ValidationError(f"{name} is a fabric host: managed by fabric (manual 1.6.13.6)")
    machine = found[0]["name"]
    command = f"sudo fabric-keytab --machine {machine} --service {service} --user {user}" + (
        f" --path {path}" if path else "")
    fqdn = found[0].get("dns") or f"{machine}.{v.get('ad_domain', '')}"
    return {"machine": machine, "command": command,
            "spns": [f"{service}/{fqdn.lower()}", f"{service}/{machine.upper()}"]}
