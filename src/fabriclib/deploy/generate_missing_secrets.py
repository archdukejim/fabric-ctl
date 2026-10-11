from fabriclib.secrets.random_password import random_password
from fabriclib.secrets.random_secret import random_secret

BASE64 = {"ca_password": 32, "rndc_secret": 32, "keycloak_admin_password": 24, "keycloak_db_password": 32,
          "kea_ddns_secret": 32,                     # HMAC-SHA256 TSIG key for Kea's DDNS
          "resolver_rndc_secret": 32}                # the BIND resolver's own control key (manual 1.12.2.4)
# alphanumeric: safe inside JSON and configuration files without quoting
ALNUM = ("webui_oidc_secret", "openbao_oidc_secret",
         "adguard_api_password")                    # fabric-agent's account in AdGuard Home (manual 1.12.3.4)


def generate_missing_secrets(secrets):
    """Purpose: create each of fabric's own secrets that does not exist yet, once (existing ones are never replaced).
    Inputs:  secrets — dict, changed in place.
    Returns: True if anything was added.
    Fails:   never.
    Feeds:   apply_deployment (before the vars are rendered: templates read the secrets)."""
    changed = False
    # Postgres creates Keycloak's user with this, once, on an empty data folder; Keycloak's password then rotates in
    # OpenBao (2.1.7.4) without touching Postgres's settings. It starts as Keycloak's (an existing install: the
    # current one, so nothing changes)
    if "postgres_init_password" not in secrets:
        secrets.setdefault("keycloak_db_password", random_secret(32))
        secrets["postgres_init_password"] = secrets["keycloak_db_password"]
        changed = True
    for name, nbytes in BASE64.items():
        if name not in secrets:
            secrets[name] = random_secret(nbytes)
            changed = True
    if "keycloak_admin_user" not in secrets:
        secrets["keycloak_admin_user"] = "admin"
        changed = True
    for name in ALNUM:
        if name not in secrets:
            secrets[name] = random_secret(alnum=True)
            changed = True
    # the Windows domain's Administrator (manual 1.6.3.7): long and of every class, so any allowed policy accepts it
    if "ad_admin_password" not in secrets:
        secrets["ad_admin_password"] = random_password()
        changed = True
    # the site's service accounts in the directory (manual 1.6.3.7): fabric-agent, Keycloak, FreeRADIUS
    for name in ("ad_agent_password", "ad_keycloak_password", "ad_radius_password"):
        if name not in secrets:
            secrets[name] = random_password()
            changed = True
    if "postgres_admin_password" not in secrets:   # Postgres's own admin, apart from Keycloak's user (2.1.7.4)
        secrets["postgres_admin_password"] = random_secret(alnum=True)
        changed = True
    if "tsig_secrets" not in secrets:
        secrets["tsig_secrets"] = {}
        changed = True
    return changed
