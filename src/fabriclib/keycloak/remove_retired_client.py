from fabriclib.keycloak.quote import q


def remove_retired_client(kc, realm, client_id):
    """Purpose: remove a Keycloak client fabric no longer uses (e.g. fabric-adguard, retired with AdGuard Home in 0.7,
             decision 2.1.12.3), with every session and token it held; nothing when it is not there.
    Inputs:  kc — keycloak/admin_client Admin; realm — fabric's realm; client_id — the retired client's clientId.
    Returns: True when it was removed, False when it was not there.
    Fails:   SystemExit from kc.call on an admin API error.
    Feeds:   nothing since 0.8.0 (its one call, for fabric-adguard, retired: stale-code register 2.3.1.5.1, S13)."""
    _, found = kc.call("GET", f"/{q(realm)}/clients?clientId={q(client_id)}")
    if not found:
        return False
    kc.call("DELETE", f"/{q(realm)}/clients/{found[0]['id']}")
    return True
