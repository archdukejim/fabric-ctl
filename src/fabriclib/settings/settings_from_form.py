from fabriclib.common.errors import ValidationError
from fabriclib.dns_filter.common.parse_upstreams import parse_upstreams
from fabriclib.samba.check_password_policy import POLICY_KEYS
from fabriclib.setup.common.parse_log_target import parse_log_target

TRUE, FALSE = ("true", "on", "yes"), ("false", "off", "no", "")


def _flag(form, field):
    """Purpose: a yes-or-no field.
    Inputs:  form — the wizard's fields; field — its name.
    Returns: bool.
    Fails:   ValidationError for another answer.
    Feeds:   settings_from_form."""
    text = str(form.get(field, "")).strip().lower()
    if text not in TRUE + FALSE:
        raise ValidationError(f"{field}: yes or no, not {form.get(field)!r}")
    return text in TRUE


def _whole(field, text):
    """Purpose: a whole-number field.
    Inputs:  field — its name (for the refusal); text — what was typed.
    Returns: int.
    Fails:   ValidationError for anything but digits.
    Feeds:   settings_from_form."""
    text = str(text or "").strip()
    if not text.isdigit():
        raise ValidationError(f"{field}: a whole number, not {text!r}")
    return int(text)


def _log_forwarding(text, base):
    """Purpose: where the logs go, from the wizard's one line (as setup asks it), keeping the rest of today's
             destination of the same kind (its index, user, TLS, message key) and the buffer's size.
    Inputs:  text — "host[:port]", an https URL, or "" for nowhere; base — today's log_forwarding (read_settings).
    Returns: the log_forwarding value.
    Fails:   ValidationError from parse_log_target.
    Feeds:   settings_from_form."""
    text = str(text or "").strip()
    keep = {k: base[k] for k in ("buffer_limit",) if k in (base or {})}
    if not text:
        return keep
    dest = parse_log_target(text)
    kind = next(iter(dest))
    return {**keep, kind: {**((base or {}).get(kind) or {}), **dest[kind]}}


def _logon_policies(text):
    """Purpose: who may sign in per OU, from the wizard's text: one OU a line, "<OU path> | <console groups> |
             <remote groups>", the groups separated by commas; "site" for the site's OU; no line at all for none (the
             rights as before 0.9).
    Inputs:  text — str.
    Returns: None, or {OU path: {"console": [...], "remote": [...]}} (checked later by check_logon_policies).
    Fails:   ValidationError for a line without two "|".
    Feeds:   settings_from_form."""
    out = {}
    for line in str(text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 3:
            raise ValidationError(f"logon_policies: {line.strip()!r}: write <OU path> | <console groups> | <remote "
                                  "groups>, e.g. machines | site-machine-admins | site-machine-admins")
        ou = parts[0].strip()
        out[ou] = {r: [g.strip() for g in p.split(",") if g.strip()] for r, p in zip(("console", "remote"), parts[1:])}
    return out or None


def settings_from_form(form, base):
    """Purpose: the wizard's fields (manual 1.8.5.3) as the settings they set, for plan_settings: each field present
             turns into its setting's value; a field left out leaves its setting as it is.
    Inputs:  form — {field: text}: dns_filter, install_fluentbit, log_target, host_ram_capacity, policy_<key> (each of
             the password policy's keys) and policy_complexity, signin_kerberos, logon_policies, dns_filter_upstreams;
             base — today's settings
             (read_settings), what a partial field keeps.
    Returns: {wizard key: value}.
    Fails:   ValidationError naming the field: a yes/no that is neither, a number that is not one, a log destination
             setup refuses, a log-on line or an upstream pair of the wrong form.
    Feeds:   agent/post_settings (POST /v1/settings/plan with the wizard's fields)."""
    out = {}
    for key in ("install_fluentbit", "signin_kerberos"):
        if key in form:
            out[key] = _flag(form, key)
    if "dns_filter" in form:
        out["dns_filter"] = str(form["dns_filter"]).strip().lower()
    if "log_target" in form:
        out["log_forwarding"] = _log_forwarding(form["log_target"], base.get("log_forwarding"))
    if "host_ram_capacity" in form:
        out["host_ram_capacity"] = _whole("host_ram_capacity", form["host_ram_capacity"])
    policy = {k: _whole(f"policy_{k}", form[f"policy_{k}"]) for k in POLICY_KEYS if f"policy_{k}" in form}
    if "policy_complexity" in form:
        policy["complexity"] = _flag(form, "policy_complexity")
    if policy:
        out["ad_password_policy"] = policy
    if "logon_policies" in form:
        out["logon_policies"] = _logon_policies(form["logon_policies"])
    if "dns_filter_upstreams" in form:
        out["dns_filter_upstreams"] = parse_upstreams(form["dns_filter_upstreams"])
    return out
