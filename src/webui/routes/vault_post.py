import time
import urllib.parse

from webui import agentclient as actions
from webui.constants import STEP_UP


def vault_post(h, sess, parts, form):
    """Purpose: Change the vault's unlock methods: rotate the key, test or remove a method, or add a USB stick,
             security key or KMIP HSM — each one fabric-agent call after a recent sign-in and the host name typed as
             confirmation.
    Inputs:  h — the request handler (back, redirect, deny); sess — dict from find_session (user, auth_at); parts — path
             segments after /openbao/: ['rotate'], ['slots', <id>, 'test'|'remove'], ['slots', 'add-usb'],
             ['slots', 'add-security-key'], ['slots', 'add-hsm']; form — confirm (must equal the host name), label,
             and per kind: disk; token ('<module>|<serial>'), key ('existing' uses key_id, else 'new'), pin; endpoint,
             key_id, server_name, ca_file / cert_file / key_file (uploads or text).
    Returns: 303 to /login?next=/secrets/unlock?signed_in=1 when the last sign-in is older than STEP_UP (300 s);
             otherwise 303 to /secrets/unlock (a test of a listed method: its page, /secrets/method?slot=<id>) with what
             was done, or why not, as its message.
    Fails:   303 with the refusal when the confirmation is not the host name, on ValidationError, and for other
             'add-…' kinds; 404 for any other path; AgentError, PermissionDenied and AuthError propagate to
             handle_request; KeyError if the agent's answer lacks key_id, dropped or id.
    Feeds:   post_action (/openbao/…).
    Notes:   The step-up is checked before the path, so even an unknown path asks for a fresh sign-in first.
    """
    if time.time() - sess.get("auth_at", 0) > STEP_UP:
        return h.redirect("/login?next=/secrets/unlock%3Fsigned_in%3D1")
    slots = actions.vault_slots()
    host, back = slots["host"], "/secrets/unlock"
    if (len(parts) == 3 and parts[:1] == ["slots"] and parts[2] == "test"   # a test: back on the method's page, when
            and any(s.get("id") == parts[1] for s in slots["slots"])):     # it is there (else its page answers 404)
        back = "/secrets/method?" + urllib.parse.urlencode({"slot": parts[1]})
    if not host or form.get("confirm", "") != host:
        return h.back(back, err=f"Type this host's name ({host}) to confirm.")
    try:
        if parts == ["rotate"]:
            res = actions.vault_rotate(sess["user"])
            msg = f"Vault key rotated to {res['key_id']}." + (
                f" Methods without their device removed: {', '.join(res['dropped'])}." if res["dropped"] else "")
        elif len(parts) == 3 and parts[0] == "slots" and parts[2] in ("test", "remove"):
            actions.vault_slot_action(sess["user"], parts[1], parts[2])
            msg = "Test passed: the method unwrapped and verified the vault key." if parts[2] == "test" else \
                "Unlock method removed."
        elif parts == ["slots", "add-usb"]:
            slot = actions.vault_add_usb(sess["user"], form.get("disk", ""), form.get("label", ""))["id"]
            msg = f"USB stick added ({slot}), read back and verified."
        elif parts == ["slots", "add-security-key"]:
            module, _, serial = form.get("token", "").rpartition("|")
            key_id = form.get("key_id", "") if form.get("key") == "existing" else "new"
            slot = actions.vault_add_security_key(sess["user"], module, serial, form.get("pin", ""), key_id,
                                                  form.get("label", ""))["id"]
            msg = f"Security key added ({slot}): the token wrapped and unwrapped the vault key."
        elif parts == ["slots", "add-hsm"]:
            pems = {f: (form.get(f) or b"").decode(errors="replace") if isinstance(form.get(f), bytes)
                    else str(form.get(f) or "") for f in ("ca_file", "cert_file", "key_file")}
            slot = actions.vault_add_kmip(form.get("endpoint", ""), form.get("key_id", ""), pems["ca_file"],
                                          pems["cert_file"], pems["key_file"], form.get("server_name", ""),
                                          form.get("label", ""))["id"]
            msg = f"HSM added ({slot}): the device wrapped and unwrapped the vault key."
        elif len(parts) == 2 and parts[0] == "slots" and parts[1].startswith("add-"):
            raise actions.ValidationError("Adding this kind of unlock method arrives in the next update.")
        else:
            return h.deny(404, "Not found.")
    except actions.ValidationError as exc:
        return h.back(back, err=str(exc))
    return h.back(back, msg=msg)
