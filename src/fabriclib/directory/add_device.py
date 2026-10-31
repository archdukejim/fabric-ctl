from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_device_fields import check_device_fields
from fabriclib.directory.common.read_directory import read_directory
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.directory.constants import DEVICE_NAME_RE


def add_device(v, actor, name, fields, source="web"):
    """Purpose: Add a device in the domain's OU=devices (manual 1.6.13.2), naming its roles on the device
             (fabricRoleName).
    Inputs:  v — fabric vars; actor — str, for the audit; name — host-name label (stripped, lower-cased,
             DEVICE_NAME_RE); fields — {type, macs, owner (username), description, enabled (default True),
             roles} (check_device_fields); source — default "web".
    Returns: the normalised device name.
    Fails:   ValidationError "device name: a host name label — ..."; "device <name> already exists";
             check_device_fields' messages; "no such user: <owner>" (from the directory);
             run_op's errors (the directory unreachable, or refusing: e.g. another site's object).
    Feeds:   agent/ (fabric-agent) Handler.directory (POST /v1/devices) -> webui agentclient.save_device.
    Notes:   runs as the site's agent account (run_op); audited as DEVICE_ADD.
    """
    name = str(name).strip().lower()
    if not DEVICE_NAME_RE.match(name):
        raise ValidationError("device name: a host name label — lowercase letters, digits and '-'")
    directory = read_directory(v)
    if any(d["name"] == name for d in directory["devices"]):
        raise ValidationError(f"device {name} already exists")
    f = check_device_fields(fields, directory, name)
    run_op(v, load_secrets(), "save_device", {"name": name, **f, "new": True})
    write_audit(actor, "DEVICE_ADD", f"device={name} type={f['type']} macs={','.join(f['macs']) or '-'} "
                                     f"roles={','.join(f['roles']) or '-'}", source)
    return name
