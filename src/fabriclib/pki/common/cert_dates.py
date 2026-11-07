import datetime
import os
import re
import subprocess

_held = {}          # path -> (the file's mtime and size, its dates): a certificate's dates never change in place


def cert_dates(cert_path):
    """Purpose: a certificate's validity.
    Inputs:  cert_path — PEM file.
    Returns: (not_before, not_after) as aware UTC datetimes, or None when openssl cannot read it.
    Fails:   FileNotFoundError only if openssl is not installed.
    Feeds:   needs_renewal, cert_warnings."""
    try:
        st = os.stat(cert_path)
    except OSError:
        return None
    same = (st.st_mtime_ns, st.st_size)
    kept = _held.get(cert_path)
    if kept and kept[0] == same:
        return kept[1]
    dates = _read_dates(cert_path)
    _held[cert_path] = (same, dates)
    return dates


def _read_dates(cert_path):
    """Purpose: a certificate's validity, as openssl reads it.
    Inputs:  cert_path — PEM file.
    Returns: (not_before, not_after), or None when openssl cannot read it.
    Fails:   FileNotFoundError only if openssl is not installed.
    Feeds:   cert_dates."""
    out = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-startdate", "-enddate"],
                         capture_output=True, text=True).stdout
    found = dict(re.findall(r"(notBefore|notAfter)=(.+)", out))
    try:
        return tuple(datetime.datetime.strptime(found[k].strip(), "%b %d %H:%M:%S %Y %Z")
                     .replace(tzinfo=datetime.timezone.utc) for k in ("notBefore", "notAfter"))
    except (KeyError, ValueError):
        return None
