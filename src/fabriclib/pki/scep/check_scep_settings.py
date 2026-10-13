from fabriclib.common.errors import ValidationError
from fabriclib.pki.scep.constants import DEFAULT_CERT_DAYS, DEFAULT_MINUTES, MAX_MINUTES, MIN_MINUTES


def check_scep_settings(final_vars):
    """Purpose: device enrolment's settings, checked at every apply (manual 1.5.3.9).
    Inputs:  final_vars — rendered settings: scep_challenge_minutes (default 60), scep_cert_days (default 365),
             pki_manual_max_days (already checked: an int).
    Returns: None; both set as ints.
    Fails:   ValidationError: scep_challenge_minutes not a whole number from 5 to 1440; scep_cert_days not a whole
             number from 1 to pki_manual_max_days.
    Feeds:   deploy/check_settings."""
    minutes = str(final_vars.get("scep_challenge_minutes", DEFAULT_MINUTES)).strip()
    if not minutes.isdigit() or not MIN_MINUTES <= int(minutes) <= MAX_MINUTES:
        raise ValidationError(f"scep_challenge_minutes must be a whole number of minutes from {MIN_MINUTES} to "
                              f"{MAX_MINUTES} (got {minutes!r})")
    cap = int(final_vars.get("pki_manual_max_days", 1825))
    days = str(final_vars.get("scep_cert_days", DEFAULT_CERT_DAYS)).strip()
    if not days.isdigit() or not 1 <= int(days) <= cap:
        raise ValidationError(f"scep_cert_days must be a whole number of days from 1 to {cap} (pki_manual_max_days; "
                              f"got {days!r})")
    final_vars["scep_challenge_minutes"], final_vars["scep_cert_days"] = int(minutes), int(days)
