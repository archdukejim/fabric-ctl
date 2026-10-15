from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_host_group_name import check_host_group_name
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def create_host_group(v, actor, name, source="cli", secrets=None, container="samba"):
    """Purpose: a new host group of this site (manual 1.6.11.7): the AD group `<site>-hosts-<name>` in its OU=groups,
             for machines, named in sudo rules (and usable in log-on policies like any group).
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the short name (or the AD name);
             source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"name": the AD name}.
    Fails:   ValidationError "host group: …" (a bad name), "that name is already taken", the directory's refusals
             (run_op), load_secrets' errors.
    Feeds:   agent route POST /v1/host-groups (machines:admin); directory/run_machines_command.
    Notes:   audited as HOST_GROUP_CREATE."""
    short = check_host_group_name(v, name)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "create_host_group", {"name": short},
                  container)
    write_audit(actor, "HOST_GROUP_CREATE", f"group={done['name']}", source)
    return done
