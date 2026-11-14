import datetime
import secrets

from webui import views
from webui.devpreview.fabric_rules import ValidationError
from webui.devpreview.fake_certs import fake_certs
from webui.devpreview.sample_data import SAMPLE_DOCTOR, SAMPLE_INFO, SAMPLE_PEM, SAMPLE_SECURITY, SAMPLE_SIZING
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
    Inputs:  state — DevState; op — describe-csr, inspect, sign, issue, convert, lookup, lifetimes, revoke; body — dict.
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
    if op == "lookup":                  # Revoke a certificate not listed: by serial only in the preview
        serial = str(body.get("serial", "")).replace(":", "").upper().lstrip("0")
        if body.get("pem"):
            raise ValidationError("this install's CA did not sign that certificate (the preview checks no files)")
        row = next((c for c in fake_certs(state)["certs"] if c["serial"] == serial), None)
        if row is None:
            raise ValidationError(f"this install's CA signed no certificate with the serial {serial} that is still "
                                  "valid: give the certificate itself to revoke one no list shows")
        return row
    if op == "lifetimes":               # PKI's Apply (2.1.5.14): the sample values change, nothing restarts
        fields = body.get("fields") or {}
        life = state.data["lifetimes"]["values"]
        life.update({k: int(v) for k, v in fields.items() if str(v).strip().isdigit() and k in life})
        for r in state.data["lifetimes"]["renewals"]:   # the next renewal moves, as the agent's read works it out
            due = datetime.date.fromisoformat(r["issued"]) + datetime.timedelta(days=life["renew_after_days"])
            r["renews"] = min(due, datetime.date.fromisoformat(r["expires"])).isoformat()
        state.log("PKI_LIFETIMES", f"dev preview: {fields}")
        return {"changed": fields, "notes": [], "stepca": "unchanged", "renewal": 0}
    if op == "revoke":                  # done at once (2.1.8.23): the sample certificate is marked revoked
        target = str(body.get("target", "")).replace(":", "").upper().lstrip("0")
        rows = state.data["issued"] + state.data["certs_other"]
        row = next((c for c in rows if c.get("serial") == target), None)
        if row is None:
            raise ValidationError(f"this install's CA signed no certificate with the serial {target}")
        cn = row["subject"].split("CN=")[-1]
        if str(body.get("confirm", "")).strip().lower() != cn.lower():
            raise ValidationError(f"type {cn!r} to confirm: nothing was revoked")
        if row["status"] == "revoked":
            raise ValidationError(f"certificate {target} is already revoked")
        row["status"] = "revoked"
        state.log("CERT_REVOKE", f"dev preview: {row['subject']} ({body.get('reason', 'unspecified')})")
        replaced = {s: "reloaded" for s in row.get("services") or []}
        return {"subject": row["subject"], "serial": target, "reason": body.get("reason", "unspecified"),
                "replaced": replaced}
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
    if route == ["events"]:
        return {}
    if route == ["kept", "refresh"]:          # as the agent: at most once per the class's lower limit (1.8.9.4)
        if body.get("read") in getattr(state, "kept_refreshed", set()):
            raise ValidationError("refreshed a moment ago: it can run again in 30 s")
        state.kept_refreshed = getattr(state, "kept_refreshed", set()) | {body.get("read")}
        return {"age_s": 0, "failed": ""}
    if route == ["sizing", "dismiss"]:
        if body.get("resource") not in {a["resource"] for a in SAMPLE_SIZING["alerts"]}:
            raise ValidationError(f"no sizing alert for {body.get('resource')!r} now")
        state.sizing_dismissed = getattr(state, "sizing_dismissed", set()) | {body["resource"]}
        return {"resource": body["resource"], "level": "warn", "objects": 7}
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
