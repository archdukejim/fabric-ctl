import datetime
import json
import os

from fabriclib.common.console import ok
from fabriclib.common.paths import CERT_RENEWAL_FILE
from fabriclib.pki.pick_up_cert import pick_up_cert
from fabriclib.setup import mint_service_certs


def _record(result, path):
    """Purpose: keep the outcome of a renewal run for status, doctor and the web console (manual 2.1.5.4).
    Inputs:  result — dict; path — CERT_RENEWAL_FILE (or a test's).
    Returns: None; the file written 0644 (no secret in it).
    Fails:   OSError writing it.
    Feeds:   renew_service_certs."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(result, f, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def renew_service_certs(ctx, force=False, scheduled=False, record=CERT_RENEWAL_FILE):
    """Purpose: renewal on a running install (`fabricctl certs [--force | --scheduled]`, the daily
             fabric-certs.timer): issue the service certificates that are due (manual 2.1.5.4) and make each changed
             service use its new one with the least interruption it allows (pick_up_cert).
    Inputs:  ctx — SetupContext (state is reloaded from vars.yaml); force — re-issue all; scheduled — the
             timer's run (quiet when nothing is due); record — where the outcome is kept.
    Returns: exit status: 0 done, 1 a certificate or a service failed (the outcome recorded either way: when, ok,
             renewed services, what each did, the error). A replaced certificate that could not be revoked
             (ctx.cert_problems, 2.1.4.8) is a failure too, recorded with what to run; the new certificate stays.
    Fails:   never raises for a renewal failure (recorded and returned as 1); OSError writing the record.
    Feeds:   cli main (`certs`), deploy/renew_landing_cert (an apply that changed the landing page's names)."""
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    result = {"when": started, "scheduled": scheduled, "ok": True, "services": {}, "error": ""}
    try:
        ctx.load_state()
        ctx.force_certs = force
        mint_service_certs.run(ctx)
        for unit in sorted(ctx.restart_services):
            how = pick_up_cert(unit)
            result["services"][unit] = how
            ok(f"{unit}: {how}")
        if not ctx.restart_services and not scheduled:
            ok("every service certificate is current")
        problems = getattr(ctx, "cert_problems", None) or []
        if problems:                             # a replaced certificate not revoked (2.1.4.8): the new one is in use
            result.update(ok=False, error="; ".join(problems)[-500:])
    except Exception as e:                   # any failure: recorded for status, doctor and the web console
        result.update(ok=False, error=str(e)[-500:])
        print(f"error: certificate renewal failed: {e}")
    _record(result, record)
    return 0 if result["ok"] else 1
