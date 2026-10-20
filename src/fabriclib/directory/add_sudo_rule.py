from fabriclib.common.write_audit import write_audit
from fabriclib.directory.common.check_sudo_rule import check_sudo_rule
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets


def add_sudo_rule(v, actor, name, users, commands, run_as=None, hosts=None, source="cli", secrets=None,
                  container="samba"):
    """Purpose: a sudo rule (manual 1.6.11.7, 1.6.13.10.10): who (people, %groups), which commands, as whom,
             on which host group (or every joined machine), stored as a `sudoRole` in the domain's OU=sudoers
             (every joined machine reads it). A rule granting ALL commands to everyone is refused.
    Inputs:  v — fabric vars; actor — str, for the audit; name — the rule's name; users, commands — lists
             of str; run_as — list of str or None (root); hosts — a host group (short or AD name), or None/"ALL";
             source — audit source; secrets — fabric's secrets (default: load_secrets()); container — the DC's
             container.
    Returns: {"name", "hosts": the sudoHost values written (a host group's machines' names, or ALL)}.
    Fails:   ValidationError from check_sudo_rule (a bad field), the directory's ("a rule granting ALL commands to
             everyone is refused …", "no person or group … in the domain", "no host group …", "that name
             is already taken"), load_secrets' errors.
    Feeds:   agent route POST /v1/sudo (sudo:admin); directory/run_sudo_command (`fabricctl sudo add`).
    Notes:   audited as SUDO_RULE_ADD with who, the commands, as whom and where."""
    rule = check_sudo_rule(v, name, users, commands, run_as, hosts)
    done = run_op(v, secrets if secrets is not None else load_secrets(), "add_sudo_rule", rule, container)
    write_audit(actor, "SUDO_RULE_ADD", f"rule={rule['name']} who={','.join(rule['users'])} "
                f"commands={','.join(rule['commands'])} as={','.join(rule['run_as'])} hosts={rule['hosts']}", source)
    return done
