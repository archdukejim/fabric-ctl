import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.grants.sync_grants import sync_grants
from fabriclib.directory.common.check_host_group_name import check_host_group_name
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

MACHINE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


def set_host_group_member(v, actor, group, machine, member, source="cli", secrets=None, container="samba"):
    """Purpose: put one of this site's machines in a host group, or take it out (manual 1.6.11.7); the sudo rules on
             that host group then name its machines again, so a rule follows its group at once.
    Inputs:  v — fabric vars; actor — str, for the audit; group — the host group (short or AD name);
             machine — the machine's host name; member — bool: in (True) or out; source — audit source; secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"group": the AD name, "machine", "member", "changed", "rules": the sudo rules whose hosts changed}.
    Fails:   ValidationError "host group: …", "machine name: …", "no host group …", "no machine … in
             OU=machines", the directory's refusals (run_op), load_secrets' errors.
    Feeds:   agent route POST /v1/host-groups/<name>/members (machines:admin); directory/run_machines_command.
    Notes:   audited as HOST_GROUP_MEMBER_ADD / HOST_GROUP_MEMBER_REMOVE when it changed something."""
    short = check_host_group_name(v, group)
    machine = machine.lower() if isinstance(machine, str) else ""
    if not MACHINE_RE.fullmatch(machine):
        raise ValidationError("machine name: 1-15 characters, a-z 0-9 and dashes, not starting or ending with a dash")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_host_group_member",
                  {"name": short, "machine": machine, "member": bool(member)}, container)
    if done["changed"]:
        write_audit(actor, "HOST_GROUP_MEMBER_ADD" if member else "HOST_GROUP_MEMBER_REMOVE",
                    f"group={done['group']} machine={machine}", source)
        sync_grants(v, actor, source, container, quiet=True)  # a grant on the group follows at once (1.6.13.4)
    return done
