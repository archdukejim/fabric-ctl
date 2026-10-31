from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_host_group_name import check_host_group_name
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def remove_host_group(v, actor, name, source="cli", secrets=None, container="samba"):
    """Purpose: delete one of this site's host groups (manual 1.6.11.7); its machines stay as they are. Refused while a
             sudo rule of fabric's names it.
    Inputs:  v — fabric vars; actor — str, for the audit; name — the short name (or the AD name);
             source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"name": the AD name}.
    Fails:   ValidationError "host group: …", "no host group …", "host group … is named by sudo rule(s) …:
             remove them first", the directory's refusals (run_op), load_secrets' errors.
    Feeds:   agent route POST /v1/host-groups/<name>/delete (machines:admin); directory/run_machines_command.
    Notes:   audited as HOST_GROUP_REMOVE."""
    short = check_host_group_name(v, name)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "remove_host_group", {"name": short},
                  container)
    write_audit(actor, "HOST_GROUP_REMOVE", f"group={done['name']}", source)
    return done
