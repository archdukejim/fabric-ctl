import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.pki.check_cert_lifetimes import acme_days, check_cert_lifetimes
from fabriclib.pki.common.cert_status import parse_cert_date
from fabriclib.pki.common.intermediate_left_days import intermediate_left_days
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.list_service_certs import list_service_certs

# the page's fields (manual 1.5.1.10.1) -> the setting each one is (ACME's in hours, the rest in days)
FIELDS = {"service_days": "cert_service_days", "renew_after_days": "cert_renew_after_days",
          "acme_days": "cert_acme_lifetime_hours", "issue_default_days": "pki_manual_default_days",
          "issue_max_days": "pki_manual_max_days"}
DEFAULTS = {"cert_service_days": 47, "cert_renew_after_days": 30, "cert_acme_lifetime_hours": "1128h",
            "pki_manual_default_days": 365, "pki_manual_max_days": 1825}


def lifetime_values(v):
    """Purpose: the page's values from the settings, in days.
    Inputs:  v — settings (FIELDS' keys; their defaults when absent).
    Returns: {field: int days}.
    Fails:   ValidationError for a setting that is not whole days (check_cert_lifetimes' wording).
    Feeds:   read_lifetimes, pki/set_lifetimes, agent/pending_thing (the Review's Was)."""
    v = {**DEFAULTS, **{k: val for k, val in v.items() if val is not None}}
    out = {}
    for field, key in FIELDS.items():
        if field == "acme_days":
            out[field] = acme_days(v)
        elif isinstance(v[key], bool) or not str(v[key]).strip().isdigit():
            raise ValidationError(f"{key} must be a whole number of days (got {v[key]!r})")
        else:
            out[field] = int(v[key])
    return out


def read_lifetimes(v, ctx, now=None, ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE):
    """Purpose: PKI → Lifetimes (decision 2.1.5.14, manual 1.5.1.10.1): the lifetimes and renewal age as set, what
             limits them, each of fabric's own certificates' next renewal under them, the 802.1X machine certificates
             running out within 30 days, and the matching setting for a LAN machine's own ACME client.
    Inputs:  v — settings; ctx — SetupContext with its vars loaded (fabric's own certificates); now — aware datetime
             (tests); ledger, revoked — the files (tests).
    Returns: {"values": lifetime_values, "intermediate_left_days" (None before the CA exists), "authority_max_hours",
             "notes" (check_cert_lifetimes' notes on the values as set), "renewals": [{"cn", "services", "issued",
             "renews" (ISO dates), "expires"}], "machines_expiring" (802.1X machine certificates, issued here and
             linked to a device, valid and ending within 30 days), "acme_client": {"certbot", "step"} (the client
             settings that match the ACME lifetime)}.
    Fails:   ValidationError for a setting that is not whole days; OSError reading the ledger.
    Feeds:   agent route GET /v1/pki/lifetimes, pki/run_certs_command (`fabricctl certs lifetimes`)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    values = lifetime_values(v)
    left = intermediate_left_days(v, now)
    try:
        notes = check_cert_lifetimes({**DEFAULTS, **v}, left)
    except ValidationError as exc:           # set before a limit applied (the intermediate has less left now)
        notes = [f"refused as set now: {exc}"]
    renewals = []
    try:
        services = list_service_certs(ctx)
    except ValidationError as exc:           # settings no setup run rendered: said, the rest still shown
        services = []
        notes.append(str(exc))
    for c in services:
        try:
            start, end = parse_cert_date(c["not_before"]), parse_cert_date(c["not_after"])
        except ValueError:
            continue
        due = min(start + datetime.timedelta(days=values["renew_after_days"]), end)
        if (end - start).days > values["service_days"] + 1:       # longer-lived than the setting: renewed at once
            due = now
        renewals.append({"cn": c["cn"], "services": c["services"], "issued": start.date().isoformat(),
                         "renews": max(due, now).date().isoformat(), "expires": end.date().isoformat()})
    machines = sum(1 for e in list_issued(limit=1000000, path=ledger, now=now, revoked=revoked)
                   if e.get("device") and e.get("status") == "expires soon")
    acme = values["acme_days"]
    return {"values": values, "intermediate_left_days": left,
            "authority_max_hours": max(values["service_days"], acme, values["issue_max_days"]) * 24,
            "notes": notes, "renewals": renewals, "machines_expiring": machines,
            "acme_client": {"certbot": f"renew_before_expiry = {max(1, -(-acme // 3))} days",
                            "step": "step ca renew --daemon renews at two thirds of the lifetime by itself"}}
