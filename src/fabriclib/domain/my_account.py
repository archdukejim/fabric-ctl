from fabriclib.common.errors import ValidationError
from fabriclib.common.paths import ISSUED_CERTS_FILE, REVOKED_CERTS_FILE
from fabriclib.domain.person_overview import person_overview


def my_account(v, user, secrets=None, container="samba", ledger=ISSUED_CERTS_FILE, revoked=REVOKED_CERTS_FILE):
    """Purpose: My account (manual 1.8.6.6), read-only: the signed-in person's own details as the DC has them (AD's
             standard attributes, 2.1.6.93), the groups they are in, the certificates fabric issued to them and the
             802.1X devices they own. Only theirs: the person is the token's user, never a name from the caller.
    Inputs:  v — rendered vars; user — the signed-in person's user name (None: root, who is no person); secrets —
             fabric's secrets (default: load_secrets()); container — the DC's container; ledger, revoked — the
             issued-certificate ledger and the revocations (tests).
    Returns: person_overview's dict for them.
    Fails:   ValidationError "a person's own account: sign in as them" for root; person_overview's (the DC not
             running, no such person: a service account).
    Feeds:   agent route GET /v1/account (any signed-in person, their own)."""
    if not user:
        raise ValidationError("a person's own account: sign in as them")
    return person_overview(v, user, secrets, container, ledger, revoked)
