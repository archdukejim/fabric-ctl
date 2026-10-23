import secrets

from webui import views
from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.sample_data import SAMPLE_DOCTOR, SAMPLE_INFO, SAMPLE_PEM, SAMPLE_SECURITY
from webui.devpreview.sample_result import sample_result
from webui.devpreview.sample_settings import SAMPLE_PLAN


def _job(state, kind, result):
    """Purpose: A background job, done at once in the preview.
    Inputs:  state — DevState; kind — "doctor", "images", "settings"; result — its result.
    Returns: {"id"}.
    Fails:   never.
    Feeds:   fake_misc."""
    jobs = state.data.setdefault("jobs", {})
    job_id = f"dev-{len(jobs) + 1}"
    jobs[job_id] = {"id": job_id, "kind": kind, "state": "done", "error": "", "result": result}
    return {"id": job_id}


def _pki(state, op, body):
    """Purpose: The PKI's forms with sample results (nothing signed or issued).
    Inputs:  state — DevState; op — describe-csr, inspect, sign, issue, convert, revoke; body — dict.
    Returns: the agent's answer, or None for another op.
    Fails:   never.
    Feeds:   fake_misc."""
    if op == "describe-csr":
        return {"pem": SAMPLE_PEM, "subject": SAMPLE_INFO["subject"], "cn": "device.home.arpa",
                "sans": SAMPLE_INFO["sans"], "key": "RSA 2048", "ca_requested": False, "problems": [],
                "text": "DEV PREVIEW — a real install shows the decoded request here."}
    if op == "inspect":
        return {"kind": "cert", "items": [{"info": SAMPLE_INFO, "trusted": True,
                                           "text": "DEV PREVIEW — a real install shows `openssl x509 -text` here."}]}
    if op in ("sign", "issue", "convert"):
        state.log(f"PKI_{op.upper()}", "dev preview: sample only, nothing signed")
        return sample_result(op)
    if op == "revoke":
        return {"subject": str(body.get("target", "")), "serial": "01", "reason": body.get("reason", "unspecified")}
    return None


def _vault(state, route, body):
    """Purpose: The vault's unlock methods acted out on the in-memory slots only (rotate, test, remove, add).
    Inputs:  state — DevState; route — segments after /v1/vault/; body — dict (disk, token, endpoint, key_id,
             label).
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError for removing the last method.
    Feeds:   fake_misc."""
    slots = state.data["slots"]
    if route == ["rotate"]:
        n = max(int(sl["key_id"].split("-")[-1]) for sl in slots) + 1
        kept = [sl for sl in slots if sl["present"]]
        dropped = [sl["id"] for sl in slots if not sl["present"]]
        for sl in kept:
            sl["key_id"] = f"fabric-{n}"
        state.data["slots"] = kept
        state.log("VAULT_ROTATE", f"new key fabric-{n} (dev preview)")
        return {"key_id": f"fabric-{n}", "dropped": dropped}
    if len(route) == 3 and route[0] == "slots" and route[2] == "remove":
        if len(slots) < 2:
            raise ValidationError("The last unlock method cannot be removed.")
        state.data["slots"] = [sl for sl in slots if sl["id"] != route[1]]
        state.log("VAULT_SLOT_REMOVE", f"{route[1]} (dev preview)")
        return {}
    if len(route) == 3 and route[0] == "slots" and route[2] == "test":
        return {}
    kind = {"add-security-key": "security-key", "add-usb": "usb", "add-hsm": "hsm"}.get(route[-1])
    if len(route) != 2 or route[0] != "slots" or not kind:
        return None
    device = {"security-key": f"YubiKey YK5 · serial {body.get('token', '')} · key 03",
              "usb": f"SanDisk Ultra Fit · {body.get('disk', '')} · UUID 9A1C-33F0",
              "hsm": f"{body.get('endpoint', 'kms')} · key {body.get('key_id', '')}"}[kind]
    slot = {"id": f"s-{secrets.token_hex(3)}", "type": kind, "label": body.get("label") or kind, "device": device,
            "present": True, "key_id": slots[0]["key_id"] if slots else "fabric-1", "added": "today",
            "detail": "dev preview: nothing was written"}
    slots.append(slot)
    state.log("VAULT_SLOT_ADD", f"{views.SLOT_TYPES[kind][0]} (dev preview)")
    return {"id": slot["id"]}


def fake_misc(state, who, route, body):
    """Purpose: The fake agent's other changes: Apply, events, jobs (doctor, an image), the PKI, the vault, sign-in
             security and the setup wizard — in memory, nothing applied.
    Inputs:  state — DevState; who — the preview's person; route — segments after /v1/; body — dict.
    Returns: the agent's answer, or None for another route.
    Fails:   ValidationError with the agent's reasons.
    Feeds:   fake_agent."""
    if route == ["apply"]:
        state.log("APPLY", "dev preview: nothing applied")
        return {"ok": True, "output": "DEV PREVIEW — nothing was rendered or reloaded.\n"
                                      "On a real install this runs `fabricctl --apply`."}
    if route == ["events"]:
        return {}
    if route == ["jobs", "doctor"]:
        return _job(state, "doctor", SAMPLE_DOCTOR)
    if route == ["jobs", "images"]:
        action, service = body.get("action"), body.get("service", "")
        if action not in ("update", "rollback") or not service:
            raise ValidationError("action: update or rollback, and a service")
        verb = "updated" if action == "update" else "rolled back"
        return _job(state, "images", {"action": action, "service": service, "moved": [service],
                                      "message": f"{verb} {service} (in memory)"})
    if len(route) == 2 and route[0] == "pki":
        return _pki(state, route[1], body)
    if route[:1] == ["vault"]:
        return _vault(state, route[1:], body)
    if route in (["security", "raise"], ["security", "kerberos"]):
        layer = "kerberos" if route[1] == "kerberos" else str(body.get("layer", ""))
        row = next((r for r in SAMPLE_SECURITY if r["layer"] == layer), {})
        was = row.get("value", "off")
        if layer == "kerberos" and str(body.get("value", "")) in ("on", "off"):
            row["value"] = str(body["value"])           # in memory: Kerberos shows it turned
        return {"layer": layer, "from": was, "to": str(body.get("value", "")), "changed": True, "applied": True}
    if route == ["settings", "plan"]:
        return {**SAMPLE_PLAN, "source": "file" if body.get("file") else "web"}
    if route == ["settings", "apply"]:
        return _job(state, "settings", {"message": "Applied (in memory): install_fluentbit, host_ram_capacity.",
                                        "output": "DEV PREVIEW — nothing was rendered or reloaded."})
    if route == ["settings", "dismiss"]:
        return {}
    return None
