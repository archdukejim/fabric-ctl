from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.write_audit import write_audit
from fabriclib.vault.common.approle_login import approle_login
from fabriclib.vault.constants import SETUP_CREDS
from fabriclib.vault.ssh.constants import HOST_CAS_PUBLISHED, HOST_PUBLISHED, USER_CAS_PUBLISHED
from fabriclib.vault.ssh.converge_ssh_ca import converge_ssh_ca
from fabriclib.vault.ssh.converge_ssh_host_ca import converge_ssh_host_ca
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key
from fabriclib.vault.ssh.publish_ssh_ca import publish_ssh_ca


def set_ssh_certificates(actor, on, source="web", login=approle_login, converge=converge_ssh_ca,
                         publish=publish_ssh_ca, converge_host=converge_ssh_host_ca):
    """Purpose: turn SSH certificates for the fabric admins on or off (manual 1.6.11.9.1; 2.1.6.39: off by default):
             OpenBao converged first, both CAs (the user CA and the host CA, 1.6.11.9.6), so a refusal saves nothing;
             then the setting saved and both CAs' public keys published (on) or withdrawn (off; with the
             organisation's lists of 2.1.7.14, which the signing run publishes while on). Safe to repeat.
             Host certificates follow at the next run of fabric-ssh-hosts.timer (1.6.11.9.8).
    Inputs:  actor — who asks (audit); on — bool; source — the audit's; login, converge, publish, converge_host —
             approle_login, converge_ssh_ca, publish_ssh_ca and converge_ssh_host_ca (tests pass their own).
    Returns: {"on": bool, "public_key", "fingerprint" ("" when there is no CA), "host_public_key",
             "host_fingerprint" (the host CA's; "" when there is none), "changed": bool (the setting)}.
    Fails:   ValidationError from OpenBao (locked, unreachable, or setup's policy without the SSH engine: run the
             vault step); OSError / yaml errors from the settings, the published file or the audit.
    Feeds:   agent route POST /v1/ssh/on, /v1/ssh/off <- the web console's SSH page."""
    with vars_lock():
        data = load_vars()
        v = dict(data)
        token = login(v, SETUP_CREDS)
        state = converge(v, token, bool(on))
        host = converge_host(v, token, bool(on))
        changed = bool(data.get("ssh_certificates", False)) != bool(on)
        if changed:
            data["ssh_certificates"] = bool(on)
            save_vars(data)
    publish(v, state["public_key"] if on else "")
    publish(v, host["public_key"] if on else "", HOST_PUBLISHED)
    if not on:              # the organisation's lists too (2.1.7.14): off, this site's machines trust no fabric CA
        publish(v, "", USER_CAS_PUBLISHED)
        publish(v, "", HOST_CAS_PUBLISHED)
    fingerprint = parse_ssh_key(state["public_key"])["fingerprint"] if state["public_key"] else ""
    host_fingerprint = parse_ssh_key(host["public_key"])["fingerprint"] if host["public_key"] else ""
    write_audit(actor, "SSH_CERTS_ON" if on else "SSH_CERTS_OFF",
                f"CA {fingerprint or '-'} host CA {host_fingerprint or '-'}"
                + ("" if changed else " (already so; converged again)"), source)
    return {"on": bool(on), "public_key": state["public_key"], "fingerprint": fingerprint,
            "host_public_key": host["public_key"], "host_fingerprint": host_fingerprint, "changed": changed}
