import datetime

from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.pki.list_issued import list_issued
from fabriclib.pki.scep.common.read_challenges import read_challenges
from fabriclib.pki.scep.constants import CHALLENGES_FILE, ENROL_KINDS


def list_enrolments(store=CHALLENGES_FILE, ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE, now=None):
    """Purpose: the web console's Enrol a device list (manual 1.5.3.7): the Apple profiles not yet used, and every
             certificate issued by enrolment with its state.
    Inputs:  store — the challenge store; ledger, revoked — the issued-certificate ledger and the revocation record;
             now — aware datetime for tests.
    Returns: {"challenges": [{id, by, made, expires, cn, device}] (open and not expired, newest first), "issued":
             list_issued's entries of kind scep or enrol-p12 (newest first), each with "link_error" ("" when none)}.
    Fails:   OSError / ValueError from the store or the ledger.
    Feeds:   agent GET /v1/pki/enrolments -> the web console's Step-CA → Enrol a device."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    items = read_challenges(store)
    open_ones = [{k: c.get(k, "") for k in ("id", "by", "made", "expires", "cn", "device")} for c in items
                 if c.get("state") == "open" and datetime.datetime.fromisoformat(c["expires"]) > now]
    errors = {str(c.get("serial")): c.get("link_error", "") for c in items if c.get("serial")}
    issued = [dict(e, link_error=errors.get(str(e.get("serial")), ""))
              for e in list_issued(limit=1000, path=ledger, revoked=revoked) if e.get("kind") in ENROL_KINDS]
    return {"challenges": sorted(open_ones, key=lambda c: c["made"], reverse=True), "issued": issued}
