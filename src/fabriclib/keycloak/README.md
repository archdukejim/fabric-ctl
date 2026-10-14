# fabriclib/keycloak

Keycloak operations over the admin REST API (TLS pinned to the fabric root
CA, admin credentials from fabric's secrets via `load_secrets`: the secrets
file, or OpenBao once imported). Realm, federation and client setup is still
in `src/ux/cli/keycloak_bootstrap.py` (to be split here), whose `Admin`
client these files use.

| File | What |
|---|---|
| `keycloak_admin.py` | Admin REST client (CA-pinned) and realm name |
| `ensure_rbac_roles.py` | A realm role per fabric permission and a composite role per bundle, converged |
| `remove_retired_client.py` | Remove a client fabric no longer uses (`fabric-adguard`, AdGuard Home retired in 0.7), if it is there |
| `ensure_openbao_client.py` | The `fabric-openbao` OIDC client for OpenBao's own UI (TOTP flow, fabric roles in a `roles` ID-token claim, exact callback) |
| `fabric_groups.py` | The directory groups that carry a fabric bundle |
| `enable_person.py` | Keycloak's copy of a person enabled again after their directory account is |
| `sign_out_person.py` | End a person's Keycloak sessions (and drop their TOTP, or Keycloak's copy of them) |
| `user_has_role.py` | Whether Keycloak grants a user a realm role (directly or through a group) |
| `verify_user_token.py` | fabric-agent: verify a signed-in person's ID token itself (signature, issuer, audience, expiry) |
| `configure_keycloak.py` | Configure Keycloak idempotently (what `lib/keycloak_bootstrap.py` runs): realm, LDAP (with Kerberos once the keytab is in place), roles, sign-in flows, clients |
| `install_sso_keytab.py` | The DC's Kerberos keytab and a `krb5.conf` into Keycloak's folder (after every converge) |
| `admin_client.py` | `Admin`: the admin REST client (logs in as the master-realm admin, TLS pinned to the fabric root CA) |
| `quote.py` | `q`: URL-quote one path or query component |
| `step.py` | One progress line of the configuration |
| `ensure_realm.py` | The realm with its login protections (brute-force lockout, no e-mail login) |
| `ensure_ldap_federation.py` | The user federation to the domain (AD mode, LDAPS to the site's DC; created, or updated in place) |
| `ensure_group_mapper.py` | The LDAP group mapper, and a sync of the directory's groups |
| `grant_role_to_group.py` | Give a group a realm role if it does not have it |
| `retire_old_admin_role.py` | The admin role's name before 0.6.4 (`fabric-admin`, now the first admin's user name) removed once the new one is in place (2.1.6.33) |
| `ensure_signin_flows.py` | fabric's sign-in flows: Kerberos or a password, then the second factor of each scope |
| `signin_levels.py` | The second-factor levels and the admin tools' effective one |
| `ensure_webui_client.py` | The web UI's OIDC client (PKCE, exact redirect, TOTP flow, roles claim) |
| `app_client_id.py` | An app's Keycloak client id for single sign-on (`app-<name>`), its name checked |
| `add_app_client.py` | `fabricctl sso add`: an app's confidential OIDC client (exact redirects, fabric's TOTP sign-in, a groups claim); its secret returned once |
| `list_app_clients.py` | `fabricctl sso list`: the registered apps, never their secrets |
| `remove_app_client.py` | `fabricctl sso remove`: an app's client gone |
| `run_sso_command.py` | `fabricctl sso`: routes to the above and prints |
| `ensure_site_group_mapper.py` | A read-only LDAP group mapper for this site's own role groups (nested membership), synced (2.1.9.21) |
| `site_bundle_grants.py` | This site's groups and the bundle each gives here only: `<site>-admins` the site helpdesk, the granted console roles (2.1.9.21) |
| `clear_lockout.py` | Keycloak's brute-force lockout of a person cleared (an unlock) |
