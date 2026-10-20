import os

import yaml

from fabriclib.directory.constants import DIRECTORY_ADMINS
from fabriclib.keycloak.admin_client import Admin
from fabriclib.keycloak.ensure_group_mapper import ensure_group_mapper
from fabriclib.keycloak.ensure_ldap_federation import ensure_ldap_federation
from fabriclib.keycloak.ensure_openbao_client import ensure_openbao_client
from fabriclib.keycloak.ensure_rbac_roles import ensure_rbac_roles
from fabriclib.keycloak.ensure_realm import ensure_realm
from fabriclib.keycloak.ensure_signin_flows import ensure_signin_flows
from fabriclib.keycloak.ensure_webui_client import ensure_webui_client
from fabriclib.keycloak.grant_role_to_group import grant_role_to_group
from fabriclib.keycloak.remove_retired_client import remove_retired_client
from fabriclib.keycloak.retire_old_admin_role import retire_old_admin_role
from fabriclib.keycloak.step import step
from fabriclib.federation.common.is_root_site import is_root_site
from fabriclib.rbac.permissions import ADMIN_ROLE, OLD_ADMIN_ROLE
from fabriclib.secrets.load_secrets import load_secrets


def configure_keycloak(vars_path, secrets_path):
    """Purpose: configure Keycloak for fabric, idempotently: realm, LDAP federation and group sync, fabric's permission
             and bundle roles with their group grants, fabric's sign-in flows (Kerberos, the second factors), and the
             fabric-webui / fabric-openbao clients; the fabric-adguard client of 0.6 is removed (AdGuard Home
             retired in 0.7).
    Inputs:  vars_path — vars.yaml; secrets_path — the secrets file (or OpenBao once imported: load_secrets). Talks to
             ip_keycloak:8443 with TLS pinned to <deploy_base_dir>/stepca/data/certs/root_ca.crt.
    Returns: None; prints progress and "Keycloak configuration complete.".
    Fails:   SystemExit (with the message) from any failed admin call or login; OSError/yaml errors reading the vars;
             ValidationError from load_secrets (OpenBao locked); KeyError when a required var or secret is missing.
    Feeds:   lib/keycloak_bootstrap.py (setup's start step, `fabricctl --keycloak-sync`, tests/keycloak/run.sh)."""
    from webui.tlsclient import TLSClient          # fabric/lib/webui: the TLS client the web UI uses too
    with open(vars_path) as f:
        v = yaml.safe_load(f)
    s = load_secrets(secrets_path, v)
    ca = os.path.join(v["deploy_base_dir"], "stepca/data/certs/root_ca.crt")
    kc = Admin(TLSClient(v["ip_keycloak"], 8443, v["hostname_keycloak"], ca),
               s["keycloak_admin_user"], s["keycloak_admin_password"])
    realm = v.get("webui_realm") or v["domain"]

    print(f"Configuring Keycloak realm {realm}...")
    realm_id = ensure_realm(kc, realm, v.get("friendly_name") or v["domain"])
    # fabric's directory, Samba AD (manual 1.6.3.11): people and groups
    writable = is_root_site(os.path.join(v["deploy_base_dir"], "fabric", "config", "federation.yaml"))
    # Kerberos sign-in (manual 2.3.6.2.6.2) once the site's DC has exported its keytab (a read-only DC cannot make one)
    kerberos = bool(v.get("signin_kerberos", False)) and os.path.exists(
        os.path.join(v["deploy_base_dir"], "keycloak", "kerberos", "sso.keytab"))
    ensure_group_mapper(kc, realm, ensure_ldap_federation(kc, realm, realm_id, v, s, writable, kerberos), v)
    # The admin role and the admin sign-in flow serve the web UI and OpenBao's UI.
    admin_role = v.get("webui_admin_role", ADMIN_ROLE)
    reps = ensure_rbac_roles(kc, realm, admin_role)
    step(f"access control: {len(reps)} fabric roles (permissions and bundles)")
    grant_role_to_group(kc, realm, reps[admin_role], DIRECTORY_ADMINS)      # the console's admins (2.1.6.81)
    if retire_old_admin_role(kc, realm, admin_role):
        step(f"the admin role is now {admin_role}: {OLD_ADMIN_ROLE} removed (2.1.6.33)")
    for group in v.get("ldap_groups") or []:
        if group.get("bundle") in reps:
            grant_role_to_group(kc, realm, reps[group["bundle"]], group["name"])
    flow_id = ensure_signin_flows(kc, realm, {**v, "signin_kerberos": kerberos})
    roles = list(reps.values())
    if v.get("install_webui"):
        ensure_webui_client(kc, realm, v, s, roles, flow_id)
    if s.get("openbao_oidc_secret"):
        step(f"{ensure_openbao_client(kc, realm, v, s['openbao_oidc_secret'], roles, flow_id)} client fabric-openbao")
    # 0.7: AdGuard Home's sign-in is gone with it (2.1.12.3); its client goes from an install that had it
    if remove_retired_client(kc, realm, "fabric-adguard"):
        step("removed client fabric-adguard (AdGuard Home retired)")
    print("Keycloak configuration complete.")
