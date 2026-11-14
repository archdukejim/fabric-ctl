import datetime

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.pki.common.cert_status import OPENSSL_DATE, cert_status, parse_cert_date
from fabriclib.pki.common.revoked_serials import norm_serial, revoked_serials
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.list_service_certs import list_service_certs
from fabriclib.pki.list_stepca_certs import list_stepca_certs

# where a certificate came from, as the Issued list's filter names it (manual 1.5.1.9.1)
SOURCES = {"here": "Issued here", "fabric": "fabric's own", "acme": "Over ACME", "8021x": "802.1X machines",
           "stepca": "Other Step-CA"}
LIVE = ("valid", "expires soon")
NAME_KINDS = ("DNS:", "IP Address:", "IP:", "email:", "URI:")   # openssl's prefixes; Step-CA's database has none


def _cn(subject):
    """Purpose: the common name of a subject, in either order openssl and Go print it ("CN=x,O=y" or "O=y,CN=x").
    Inputs:  subject — str.
    Returns: the CN's value, or "" without one.
    Fails:   never.
    Feeds:   list_certs."""
    for part in str(subject or "").replace("/", ",").split(","):
        key, _, value = part.strip().partition("=")
        if key.strip().upper() == "CN":
            return value.strip()
    return ""


def _row(source, serial, subject, sans, end, gone, now, **extra):
    """Purpose: one row of the Issued list, the same shape whatever its source.
    Inputs:  source — a SOURCES key; serial — hex (any form); subject — str; sans — list; end — expiry (aware
             datetime); gone — the revoked serials; now — aware datetime; extra — the source's own fields.
    Returns: dict: serial (normalised), subject, cn, sans (the names alone, openssl's "DNS:" and the like taken
             off, as every source shows them the same), not_after (openssl's form), status, source, revocable, and
             extra.
    Fails:   never.
    Feeds:   list_certs."""
    serial = norm_serial(serial)
    status = cert_status(end, serial in gone, now)
    names = []
    for name in sans or []:
        name = str(name).strip()
        kind = next((k for k in NAME_KINDS if name.startswith(k)), "")
        names.append(name[len(kind):].strip())
    return {"serial": serial, "subject": subject, "cn": _cn(subject), "sans": names,
            "not_after": end.strftime(OPENSSL_DATE).replace("UTC", "GMT"), "status": status, "source": source,
            "revocable": status in LIVE, **extra}


def list_certs(v, ctx, now=None, ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE, stepca=list_stepca_certs,
               devices=None):
    """Purpose: every certificate the console can revoke (decision 2.1.5.13, manual 1.5.1.9.1), each marked by where
             it came from: issued here (the ledger), fabric's own service certificates (on disk), LAN machines' over
             ACME and anything else Step-CA signed (its database, through a copy), and 802.1X machines' (a ledger
             certificate linked to a device, or Step-CA's over SCEP). A certificate in several is listed once: the
             ledger first, then the service certificates, then the database.
    Inputs:  v — settings; ctx — SetupContext with its vars loaded (service certificates); now — aware datetime
             (tests); ledger, revoked — the files (tests); stepca — the database reader (tests); devices — the
             directory's devices ({name: device}), or None when the directory cannot be read (rows keep the name).
    Returns: {"certs": rows, newest ledger entries first, then fabric's own, then the database's (its expired ones
             left out: nothing to revoke); "stepca_error": why Step-CA's database could not be read ("" when it was),
             "service_error": why fabric's own could not be found ("" when they were),
             "sources": SOURCES}. A row: serial, subject, cn, sans, not_after, status, source, revocable, and its
             source's fields: kind, actor, when, sha256, device, device_roles, how (802.1X), services (fabric's own),
             provisioner (Step-CA's).
    Fails:   OSError reading the ledger or the revocations.
    Feeds:   agent route GET /v1/pki/certs; pki/find_cert; pki/revoke_cert."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    gone = revoked_serials(revoked)
    devices = devices or {}
    rows, seen = [], set()
    for e in list_issued(limit=1000000, path=ledger, now=now, revoked=revoked):
        try:
            end = parse_cert_date(e.get("not_after"))
        except ValueError:
            continue
        extra = {k: e.get(k) for k in ("kind", "actor", "when", "sha256", "key")}
        source = "here"
        if e.get("device"):                       # a certificate a device uses for EAP-TLS (1.11.1)
            source = "8021x"
            dev = devices.get(e["device"]) or {}
            extra.update(device=e["device"], device_roles=list(dev.get("roles") or []),
                         how={"csr": "CSR signed here", "keypair": "key + certificate (PKCS#12)",
                              "scep": "SCEP"}.get(e.get("kind"), e.get("kind") or ""))
        row = _row(source, e.get("serial", ""), e.get("subject", ""), e.get("sans"), end, gone, now, **extra)
        seen.add(row["serial"])
        rows.append(row)
    service_error = ""
    try:
        services = list_service_certs(ctx)
    except ValidationError as exc:                # settings no setup run rendered: said on the page
        services, service_error = [], str(exc)
    for c in services:
        if norm_serial(c["serial"]) in seen:
            continue
        try:
            end = parse_cert_date(c["not_after"])
        except ValueError:
            continue
        rows.append(_row("fabric", c["serial"], c["subject"], c["sans"], end, gone, now, services=c["services"],
                         service_cn=c["cn"], sha256=c["sha256"]))
        seen.add(norm_serial(c["serial"]))
    error = ""
    try:
        signed = stepca(v)
    except ValidationError as exc:
        signed, error = [], str(exc)
    for c in signed:
        if norm_serial(c["serial"]) in seen or c.get("is_ca"):
            continue
        try:
            end = parse_cert_date(c["not_after"])
        except ValueError:
            continue
        if end < now:                             # expired: nothing left to revoke
            continue
        kind = str(c.get("provisioner_type") or "").upper()
        source = {"ACME": "acme", "SCEP": "8021x"}.get(kind, "stepca")
        extra = {"provisioner": c.get("provisioner", ""), "provisioner_type": c.get("provisioner_type", "")}
        if source == "8021x":
            extra.update(device="", device_roles=[], how="SCEP")
        rows.append(_row(source, c["serial"], c["subject"], c["sans"], end, gone, now, **extra))
        seen.add(norm_serial(c["serial"]))
    return {"certs": rows, "stepca_error": error, "service_error": service_error, "sources": dict(SOURCES)}
