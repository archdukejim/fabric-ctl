import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.save_vars import save_vars
from fabriclib.common.vars_lock import vars_lock
from fabriclib.common.wait_healthy import wait_healthy
from fabriclib.common.write_audit import write_audit
from fabriclib.pki.check_cert_lifetimes import authority_max_hours, check_cert_lifetimes
from fabriclib.pki.common.intermediate_left_days import intermediate_left_days
from fabriclib.pki.read_lifetimes import DEFAULTS, FIELDS, lifetime_values


def lifetime_changes(v, given):
    """Purpose: the settings a Lifetimes change writes, checked against the real limits (manual 1.5.1.10.2) before
             anything is written: what PKI's hold and its Apply both check.
    Inputs:  v — the settings now; given — {field: days} for some of FIELDS (str or int; "" or None: unchanged).
    Returns: (changed — {setting: (old, new)} for the settings that differ, notes — check_cert_lifetimes' notes).
    Fails:   ValidationError, nothing changed: an unknown field, a value that is not a whole number of days, what
             check_cert_lifetimes refuses (the intermediate's days left, for the values changed).
    Feeds:   set_lifetimes, agent/post_pending (the hold's check), agent/pending_thing (the Review)."""
    unknown = sorted(set(given) - set(FIELDS))
    if unknown:
        raise ValidationError(f"unknown lifetime field(s): {', '.join(unknown)} (one of {', '.join(FIELDS)})")
    now = lifetime_values(v)
    new = dict(now)
    for field, value in given.items():
        text = "" if value is None else str(value).strip()
        if text == "":
            continue
        if not text.isdigit():
            raise ValidationError(f"{field.replace('_', ' ')} must be a whole number of days (got {text!r})")
        new[field] = int(text)
    settings = {**DEFAULTS, **v, **{FIELDS[f]: (f"{d * 24}h" if f == "acme_days" else d) for f, d in new.items()}}
    changed = {}
    for field in FIELDS:
        if new[field] != now[field]:
            changed[FIELDS[field]] = (v.get(FIELDS[field], DEFAULTS[FIELDS[field]]), settings[FIELDS[field]])
    notes = check_cert_lifetimes(settings, intermediate_left_days(v), only=set(changed))
    return changed, notes


def _restart_stepca(run):
    """Purpose: restart Step-CA so it reads its converged ca.json, and wait until it answers.
    Inputs:  run — subprocess.run (tests).
    Returns: "restarted".
    Fails:   ValidationError when the restart fails or Step-CA is not healthy within two minutes.
    Feeds:   set_lifetimes."""
    if run(["systemctl", "restart", "stepca"], capture_output=True, text=True).returncode != 0:
        raise ValidationError("the lifetimes are saved, but Step-CA did not restart: see `fabricctl status`")
    ok, why = wait_healthy("step-ca", timeout=120)
    if not ok:
        raise ValidationError(f"the lifetimes are saved, but Step-CA is not healthy after its restart ({why})")
    return "restarted"


def set_lifetimes(actor, given, source="cli", ctx=None, run=subprocess.run, converge=None, renew=None):
    """Purpose: PKI → Lifetimes' Apply and `fabricctl certs lifetimes --…` (decision 2.1.5.14, manual 1.5.1.10.3):
             save the lifetimes and renewal age, converge Step-CA's ca.json (the ACME provisioner's lifetime, the
             authority's maximum worked out from them) and restart it when that changed, then renew at once, as the
             daily timer would, each of fabric's own certificates the new values say is due. Certificates already
             issued keep their expiry until they are renewed.
    Inputs:  actor — who (audit); given — {field: days} (read_lifetimes.FIELDS); source — "cli" | "web"; ctx —
             SetupContext (made for the install when None); run — subprocess.run (tests); converge — (ca_json, v) ->
             bool (default init_pki._configure_ca_json); renew — ctx -> exit status (default renew_service_certs).
    Returns: {"changed": {setting: [old, new]}, "notes", "stepca": "restarted" | "unchanged", "renewal": 0 | 1}
             ({"changed": {}} and nothing done when every value is as set).
    Fails:   ValidationError, nothing changed: lifetime_changes' refusals. After saving: ValidationError when Step-CA
             does not restart healthy or the renewal fails (the settings stay saved; the renewal is recorded for
             status and doctor as the timer's is). OSError writing the settings.
    Feeds:   agent route POST /v1/pki/lifetimes (held for PKI's Apply), pki/run_certs_command."""
    from fabriclib.setup.context import SetupContext            # imported here: setup imports pki
    with vars_lock():
        v = load_vars()
        changed, notes = lifetime_changes(v, given)
        if not changed:
            return {"changed": {}, "notes": notes, "stepca": "unchanged", "renewal": 0}
        for key, (_old, new) in changed.items():
            v[key] = new
        v["stepca_cert_max_lifetime_hours"] = authority_max_hours(v)
        save_vars(v)
    write_audit(actor, "PKI_LIFETIMES", " ".join(f"{k}={old}->{new}" for k, (old, new) in changed.items()), source)
    if converge is None:
        from fabriclib.setup.init_pki import _configure_ca_json as converge
    ca_json = f"{v['deploy_base_dir']}/stepca/data/config/ca.json"
    stepca = _restart_stepca(run) if converge(ca_json, v) else "unchanged"
    if ctx is None:
        ctx = SetupContext(deploy_base=v["deploy_base_dir"])
    if renew is None:
        from fabriclib.setup.renew_service_certs import renew_service_certs as renew
    status = renew(ctx)
    out = {"changed": {k: list(pair) for k, pair in changed.items()}, "notes": notes, "stepca": stepca,
           "renewal": status}
    if status != 0:
        raise ValidationError("the lifetimes are saved and Step-CA uses them, but renewing fabric's own certificates "
                              "failed: see `fabricctl status` (the timer retries tonight)")
    return out
