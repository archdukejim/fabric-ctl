import time

from fabriclib.secrets.load_secrets import load_secrets


def list_invitations(v, now=None):
    """Purpose: the invitations this upstream has made that are still open, without their secrets' hashes.
    Inputs:  v — fabric vars (for OpenBao); now — epoch seconds, default time.time().
    Returns: list of {"id", "site", "expires", "actor", "kind"}, soonest-expiring first; expired ones are left out;
             kind is "join" (an invitation) or "dc-type" (a DC type change token, 2.1.9.23).
    Fails:   ValidationError from load_secrets (OpenBao locked); OSError.
    Feeds:   run_federation_command (invitations), federation_status."""
    now = now if now is not None else time.time()
    open_invites = (load_secrets(v=v).get("federation_invitations") or {}).items()
    return sorted(({"id": i, "site": e.get("site"), "expires": e.get("expires"), "actor": e.get("actor"),
                    "kind": e.get("kind") or "join"}
                   for i, e in open_invites if e.get("expires", 0) > now), key=lambda e: e["expires"])
