import datetime
import os

from fabriclib.pki.common.cert_dates import cert_dates


def intermediate_left_days(v, now=None):
    """Purpose: how long this install's intermediate CA has left: no certificate Step-CA signs can outlive it
             (decision 2.1.5.14, manual 1.5.1.10.2).
    Inputs:  v — settings (deploy_base_dir); now — aware datetime (tests).
    Returns: whole days left (int, 0 once expired), or None before the CA exists (or when its file is unreadable).
    Fails:   FileNotFoundError only without openssl.
    Feeds:   deploy/render_vars, pki/read_lifetimes, pki/set_lifetimes."""
    path = os.path.join(v.get("deploy_base_dir") or "/opt", "stepca", "data", "certs", "intermediate_ca.crt")
    dates = cert_dates(path) if os.path.exists(path) else None
    if dates is None:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0, int((dates[1] - now).total_seconds() // 86400))
