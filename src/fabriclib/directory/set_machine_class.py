from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.directory.run_op import run_op
from fabriclib.secrets.load_secrets import load_secrets

CLASSES = ("server", "desktop")      # the DC's: src/containers/samba/site_roles.CLASSES


def set_machine_class(v, actor, name, machine_class, source="cli", secrets=None, container="samba"):
    """Purpose: change a machine's class, server or desktop (2.1.6.36 as revised 2026-10-13, manual 1.6.11.5): its
             account moved into that class's OU, so `<site>-<class>-remote-users` decides who may sign in to it
             remotely, by SSH and RDP alike (2.1.7.14's second revision); a Linux member's SSH principals follow
             on its next fabric-managed run (join-linux.sh). The site's fabric host is refused (2.1.6.53).
    Inputs:  v — fabric vars (site_name); actor — str, for the audit; name — the machine's host name; machine_class —
             "server" or "desktop"; source — audit source; secrets — fabric's secrets (default: load_secrets());
             container — the DC's container (tests name their own).
    Returns: {"name", "class", "dn", "changed"}.
    Fails:   ValidationError "class: …" for another class; run_op's ("no such entry": not a machine of this site;
             the fabric host; the DC not reachable).
    Feeds:   samba/run_domain_command (`fabricctl domain machine class`).
    Notes:   audited as MACHINE_CLASS when it changed something."""
    if machine_class not in CLASSES:
        raise ValidationError(f"class: one of {', '.join(CLASSES)}, not {machine_class!r}")
    done = run_op(v, secrets if secrets is not None else load_secrets(), "set_machine_class",
                  {"name": name, "machine_class": machine_class}, container)
    if done.get("changed"):
        write_audit(actor, "MACHINE_CLASS", f"machine={name} class={machine_class}", source)
    return done
