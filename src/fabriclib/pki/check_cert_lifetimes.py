from fabriclib.common.errors import ValidationError

MIN_ROOT_DAYS = 365
MIN_SERVICE_DAYS = 2       # the renewal runs once a day (fabric-certs.timer): it needs a run before the end
MIN_LEFT_DAYS = 1          # renew at least a day before the end, for the same reason (2.1.5.14)
NOTE_LEFT_DAYS = 7         # under this, the certificate shows as expiring soon every cycle (2.1.5.4): a note
NOTE_SERVER_DAYS = 398     # the cap browsers set for the public CAs they ship with, not for fabric's root: a note


def _days(v, key):
    """Purpose: one lifetime setting as whole days.
    Inputs:  v — settings; key — the setting's name.
    Returns: int.
    Fails:   ValidationError when it is not a whole number.
    Feeds:   check_cert_lifetimes, acme_days."""
    value = v.get(key)
    if isinstance(value, bool) or not str(value).strip().isdigit():
        raise ValidationError(f"{key} must be a whole number of days (got {value!r})")
    return int(value)


def acme_days(v):
    """Purpose: the ACME lifetime in days, from its setting in hours (cert_acme_lifetime_hours, "1128h").
    Inputs:  v — settings (cert_acme_lifetime_hours, default "1128h").
    Returns: int days.
    Fails:   ValidationError when it is not a whole number of days in hours ("<n>h", n a multiple of 24).
    Feeds:   check_cert_lifetimes, pki/read_lifetimes."""
    text = str(v.get("cert_acme_lifetime_hours", "1128h")).strip().lower()
    hours = text[:-1] if text.endswith("h") else text
    if not hours.isdigit() or int(hours) % 24:
        raise ValidationError(f"cert_acme_lifetime_hours must be whole days in hours, such as 1128h (got {text!r})")
    return int(hours) // 24


def authority_max_hours(v):
    """Purpose: Step-CA's maximum for the whole authority, worked out from the lifetimes it must allow (decision
             2.1.5.14): the longest of fabric's own, ACME's and the hand-issued maximum (vars.yaml.j2 renders the same).
    Inputs:  v — settings (cert_service_days, cert_acme_lifetime_hours, pki_manual_max_days; their defaults).
    Returns: "<hours>h".
    Fails:   ValidationError from _days or acme_days.
    Feeds:   pki/set_lifetimes."""
    v = {"cert_service_days": 47, "pki_manual_max_days": 1825, **v}
    return f"{max(_days(v, 'cert_service_days') * 24, acme_days(v) * 24, _days(v, 'pki_manual_max_days') * 24)}h"


def check_cert_lifetimes(v, intermediate_left_days=None, only=None):
    """Purpose: refuse only certificate lifetimes that could not work (decision 2.1.5.14, "only the real limits";
             manual 1.5.1.10.2, 2.1.5.6), and say what is allowed but worth knowing.
    Inputs:  v — the settings: cert_service_days, cert_renew_after_days, cert_root_ca_days (default 3650),
             cert_acme_lifetime_hours (default "1128h"), pki_manual_default_days (default 365), pki_manual_max_days
             (default 1825); intermediate_left_days — the days the intermediate CA has left (None before the CA
             exists, or a setup run: not checked); only — the settings being changed (None: all), the ones the
             intermediate's limit applies to: a value set when the intermediate had longer left is not refused as it
             ages (its renewal, 1.5.1.6, is what fixes that).
    Returns: list of notes (str), each about a value that is allowed: a server certificate over 398 days, renewal
             under 7 days before the end.
    Fails:   ValidationError naming the setting: not a whole number of days; fabric's own lifetime under 2 days, renew
             at under 1 day or less than 1 day before the end; any lifetime longer than the intermediate has left
             (Step-CA would cut it at the intermediate's expiry); the hand-issued default over its maximum;
             cert_root_ca_days under 365.
    Feeds:   deploy/render_vars (every setup run, without the intermediate's limit), pki/set_lifetimes (PKI →
             Lifetimes, `fabricctl certs lifetimes`)."""
    v = {"cert_root_ca_days": 3650, "pki_manual_default_days": 365, "pki_manual_max_days": 1825, **v}
    service, renew, root = (_days(v, k) for k in ("cert_service_days", "cert_renew_after_days", "cert_root_ca_days"))
    default, most, acme = _days(v, "pki_manual_default_days"), _days(v, "pki_manual_max_days"), acme_days(v)
    if service < MIN_SERVICE_DAYS:
        raise ValidationError(f"cert_service_days is {service}: fabric's own certificates live at least "
                              f"{MIN_SERVICE_DAYS} days, so the daily renewal has a run before one expires")
    if renew < 1:
        raise ValidationError(f"cert_renew_after_days is {renew}: renewal starts at least a day after issue")
    if service - renew < MIN_LEFT_DAYS:
        raise ValidationError(f"cert_renew_after_days {renew} leaves {service - renew} day(s) of a {service}-day "
                              f"certificate: renew at least {MIN_LEFT_DAYS} day before the end, so the daily renewal "
                              f"runs before it expires (renew at {service - MIN_LEFT_DAYS} days at most)")
    if acme < 1:
        raise ValidationError("cert_acme_lifetime_hours is 0: an ACME certificate lives at least a day")
    if default < 1 or most < 1:
        raise ValidationError("pki_manual_default_days and pki_manual_max_days are at least 1 day")
    if default > most:
        raise ValidationError(f"pki_manual_default_days {default} is over the hand-issued maximum, "
                              f"pki_manual_max_days {most}")
    if root < MIN_ROOT_DAYS:
        raise ValidationError(f"cert_root_ca_days is {root}: the root CA lives at least {MIN_ROOT_DAYS} days "
                              "(its intermediate lives a year less)")
    if intermediate_left_days is not None:
        for key, days in (("cert_service_days", service), ("cert_acme_lifetime_hours", acme),
                          ("pki_manual_default_days", default), ("pki_manual_max_days", most)):
            if days > intermediate_left_days and (only is None or key in only):
                raise ValidationError(f"{key} is {days} days, longer than the intermediate CA has left "
                                      f"({intermediate_left_days} days): Step-CA would cut such a certificate at the "
                                      "intermediate's own expiry")
    notes = []
    for label, days in (("fabric's own certificates", service), ("ACME certificates", acme)):
        if days > NOTE_SERVER_DAYS:
            notes.append(f"{label} live {days} days, over {NOTE_SERVER_DAYS}: browsers cap the public CAs they ship "
                         "with there, not a root a person or an administrator installs, as fabric's is; a device "
                         "that does not treat fabric's root that way may refuse them")
    if service - renew < NOTE_LEFT_DAYS:
        notes.append(f"fabric's own certificates are renewed {service - renew} day(s) before they end: under "
                     f"{NOTE_LEFT_DAYS}, each shows as expiring soon every cycle, and a failed night leaves little "
                     "time to fix it")
    return notes
