from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.constants import SETUP_CREDS
from fabriclib.vault.ssh.converge_ssh_ca import converge_ssh_ca
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key
from fabriclib.vault.ssh.publish_ssh_ca import publish_ssh_ca


def set_ssh_certificates(actor, on, source="web", login=approle_login, converge=converge_ssh_ca,
                         publish=publish_ssh_ca):
    """Purpose: turn SSH certificates for the fabric admins on or off (manual 1.6.11.9.1; 2.1.6.39: off by default):
             OpenBao converged first, so a refusal saves nothing; then the setting saved and the CA's public key
             published (on) or withdrawn (off). Safe to repeat.
    Inputs:  actor — who asks (audit); on — bool; source — the audit's; login, converge, publish — approle_login,
             converge_ssh_ca and publish_ssh_ca (tests pass their own).
    Returns: {"on": bool, "public_key", "fingerprint" ("" when there is no CA), "changed": bool (the setting)}.
    Fails:   ValidationError from OpenBao (locked, unreachable, or setup's policy without the SSH engine: run the
             vault step); OSError / yaml errors from the settings, the published file or the audit.
    Feeds:   agent route POST /v1/ssh/on, /v1/ssh/off <- the web console's SSH page."""
    with vars_lock():
        data = load_vars()
        v = dict(data)
        state = converge(v, login(v, SETUP_CREDS), bool(on))
        changed = bool(data.get("ssh_certificates", False)) != bool(on)
        if changed:
            data["ssh_certificates"] = bool(on)
            save_vars(data)
    publish(v, state["public_key"] if on else "")
    fingerprint = parse_ssh_key(state["public_key"])["fingerprint"] if state["public_key"] else ""
    write_audit(actor, "SSH_CERTS_ON" if on else "SSH_CERTS_OFF",
                f"CA {fingerprint or '-'}" + ("" if changed else " (already so; converged again)"), source)
    return {"on": bool(on), "public_key": state["public_key"], "fingerprint": fingerprint, "changed": changed}
