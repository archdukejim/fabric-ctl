import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

RULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$")


def remove_sudo_rule(v, actor, name, source="cli", secrets=None, container="samba"):
    """Purpose: remove a sudo rule fabric's editor made (manual 1.6.11.7). The site's default rule (1.6.11.3) and the
             rules admins made with their own tools are refused, saying so.
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the rule's name; source — audit source;
             secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"name"}.
    Fails:   ValidationError "rule name: …", "no sudo rule … in site …", "… is the site's default rule …", "… was not
             made by fabric's sudo editor …", the directory's refusals (run_op), load_secrets' errors.
    Feeds:   agent route POST /v1/sudo/<name>/delete (sudo:admin); directory/run_sudo_command (`fabricctl sudo
             remove`).
    Notes:   audited as SUDO_RULE_REMOVE."""
    if not isinstance(name, str) or not RULE_RE.fullmatch(name):
        raise ValidationError("rule name: letters, digits, spaces, dots, dashes and underscores, at most 63")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "remove_sudo_rule", {"name": name},
                  container)
    write_audit(actor, "SUDO_RULE_REMOVE", f"rule={done['name']}", source)
    return done
