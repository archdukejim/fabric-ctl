import datetime
import json
import os
import re

from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.common.write_audit import write_audit
from fabriclib.pki.common.revoked_serials import norm_serial, revoked_serials
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.pick_up_cert import pick_up_cert
from fabriclib.pki.publish_crl import REASONS, publish_crl

SERIAL_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:?){1,20}$|^[0-9A-Fa-f]{1,40}$")   # a serial printed with or without colons


def _issuer_of(entry):
    """Purpose: which of this install's CAs signed a ledger entry: the root for a site's CA it signed flat, the
             intermediate for everything else (leaves, and a site nested under this one).
    Inputs:  entry — a ledger entry (kind, issuer).
    Returns: "root" or "intermediate".
    Fails:   never.
    Feeds:   revoke_cert."""
    if entry.get("kind") != "site-ca":
        return "intermediate"
    return "intermediate" if "Intermediate" in (entry.get("issuer") or "") else "root"


def _lookup(v, ctx, serial="", pem=""):
    """Purpose: a certificate the ledger does not name, from every list the console shows (manual 1.5.1.9): fabric's
             own service certificates and Step-CA's database.
    Inputs:  v — settings; ctx — SetupContext with vars loaded, or None (one is made from v); serial, pem — as
             find_cert.
    Returns: find_cert's row.
    Fails:   find_cert's ValidationError.
    Feeds:   revoke_cert (its default lookup)."""
    from fabriclib.pki.find_cert import find_cert           # imported here: list_certs imports list_issued
    from fabriclib.pki.list_certs import list_certs
    from fabriclib.setup.context import SetupContext
    if ctx is None:
        ctx = SetupContext(deploy_base=v["deploy_base_dir"])
        ctx.vars = v
    return find_cert(v, list_certs(v, ctx), serial=serial, pem=pem)


def revoke_cert(v, actor, target, reason="unspecified", source="cli", ledger=ISSUED_CERTS_FILE,
                revoked=REVOKED_CERTS_FILE, publish=True, pem="", confirm=None, ctx=None, lookup=None,
                replace=None):
    """Purpose: revoke a certificate fabric's CA signed (manual 2.1.5.10, 1.5.1.9): record it and publish the CRLs at
             once, so FreeRADIUS and the web console refuse it even while a device is still linked. One of fabric's
             own service certificates is issued again and put in use first (1.5.1.9.4); if that fails, nothing is
             revoked.
    Inputs:  v — settings; actor — who (audit); target — a serial (hex, colons allowed) or a name: the subject's CN of
             one certificate in the issued-certificate ledger ("" when pem is given); reason — one of REASONS;
             source — "cli" | "web"; ledger, revoked, publish — for tests; pem — the certificate itself (1.5.1.9.2);
             confirm — the name the person typed again (the console's confirmation, 1.5.1.9.3): the certificate's CN,
             or its serial when it has none; None skips the check (the command line, people/remove_person);
             ctx — SetupContext with vars loaded (service certificates; made from v when None); lookup — (v, ctx,
             serial, pem) -> row for what the ledger does not name (tests; default: list_certs and find_cert);
             replace — (ctx, cn) -> {service: how} (tests; default replace_service_cert).
    Returns: {"serial", "subject", "issuer", "reason", "replaced"} of the revoked certificate ("replaced": the services
             that took a new one, {} for any other certificate).
    Fails:   ValidationError, nothing changed: an unknown reason; a target that is neither a serial nor a name in the
             ledger, or a name matching several certificates (use the serial); a serial or file find_cert refuses
             (not signed here, not a certificate, the CA's own); a confirmation that is not the certificate's name; a
             certificate already revoked; a site CA signed by the root on a host without the root key (its CRL cannot
             be signed here); a service certificate whose successor cannot be issued. subprocess.CalledProcessError
             from publish_crl or from reloading nginx / restarting FreeRADIUS.
    Feeds:   cli (`fabricctl certs revoke`), agent route POST /v1/pki/revoke, people/remove_person (their
             certificates)."""
    if reason not in REASONS:
        raise ValidationError(f"unknown reason {reason!r}: one of {', '.join(REASONS)}")
    target = (target or "").strip()
    lookup = lookup or _lookup
    entries = list_issued(limit=1000000, path=ledger)
    if pem:
        entry = lookup(v, ctx, pem=pem)
    elif SERIAL_RE.match(target) and not any(e.get("subject", "").endswith(f"CN={target}") for e in entries):
        found = [e for e in entries if norm_serial(str(e.get("serial", ""))) == norm_serial(target)]
        entry = found[0] if found else lookup(v, ctx, serial=target)
    else:
        found = [e for e in entries if re.search(rf"(^|,)CN={re.escape(target)}(,|$)", e.get("subject") or "")]
        live = [e for e in found if e.get("status") != "expired"]
        if not found:
            raise ValidationError(f"no certificate named {target!r} in the issued-certificate ledger: give its serial "
                                  "(fabricctl certs issued, or the web console's PKI page)")
        if len(live) > 1:
            raise ValidationError(f"{len(live)} certificates are named {target!r}: give the serial of the one to "
                                  "revoke (" + ", ".join(str(e.get('serial')) for e in live) + ")")
        entry = (live or found)[0]
    if confirm is not None:
        cn = next((p.strip()[3:] for p in str(entry.get("subject") or "").split(",")
                   if p.strip().upper().startswith("CN=")), "")
        wanted = cn or norm_serial(str(entry["serial"]))
        if str(confirm).strip().lower() != wanted.lower():
            raise ValidationError(f"type {wanted!r} to confirm: nothing was revoked")
    serial = norm_serial(str(entry["serial"]))
    if serial in revoked_serials(revoked):
        raise ValidationError(f"certificate {serial} is already revoked")
    if entry.get("source") == "file" and entry.get("is_ca"):
        entry = {**entry, "kind": "site-ca", "issuer": entry.get("issuer_dn", "")}
    issuer = _issuer_of(entry)
    secrets = os.path.join(v["deploy_base_dir"], "stepca", "data", "secrets")
    if issuer == "root" and not os.path.exists(os.path.join(secrets, "root_ca_key")):
        raise ValidationError("this site CA was signed by the root, whose key is not on this host (a brought-in "
                              "root): revoke it where the root key is")
    replaced = {}
    if entry.get("source") == "fabric":      # fabric's own: its successor in use first, or nothing is revoked
        if ctx is None:
            from fabriclib.setup.context import SetupContext
            ctx = SetupContext(deploy_base=v["deploy_base_dir"])
            ctx.vars = v
        if replace is None:
            from fabriclib.pki.replace_service_cert import replace_service_cert as replace
        replaced = replace(ctx, entry["service_cn"])
    record = {"serial": serial, "when": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
              "actor": actor, "source": source, "reason": reason, "issuer": issuer,
              "subject": entry.get("subject", ""), "not_after": entry.get("not_after", "")}
    os.makedirs(os.path.dirname(revoked), mode=0o700, exist_ok=True)
    fd = os.open(revoked, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(record) + "\n")
    write_audit(actor, "PKI_REVOKE", f"serial={serial} subject={record['subject']} reason={reason}"
                + (f" replaced={','.join(sorted(replaced))}" if replaced else ""), source)
    if publish:                              # in force at once: nginx reloads, FreeRADIUS restarts (seconds)
        crl = publish_crl(v, revoked_file=revoked)
        if crl["changed"]:
            pick_up_cert("nginx")
        if crl["radius_changed"]:
            pick_up_cert("freeradius")
    return {**{k: record[k] for k in ("serial", "subject", "issuer", "reason")}, "replaced": replaced}
