from fabriclib.keycloak.quote import q
from fabriclib.keycloak.step import step

USER_STORAGE = "org.keycloak.storage.UserStorageProvider"
NAME = "Samba AD"
KEYTAB = "/etc/keycloak/kerberos/sso.keytab"   # inside the container (install_sso_keytab writes it)
MATCH_BIT, ACCOUNTDISABLE = "1.2.840.113556.1.4.803", 2      # LDAP_MATCHING_RULE_BIT_AND; userAccountControl's bit


def ensure_ldap_federation(kc, realm, realm_id, v, s, writable=True, kerberos=False):
    """Purpose: the realm's user federation to fabric's directory, Samba AD (manual 1.6.3.11, 1.6.5.16 S2.5): AD mode,
             LDAPS to the DC at the host's address (verified against fabric's CA), bound as this DC's Keycloak
             account, fabric-keycloak-<dc_name> in OU=service-accounts (2.1.6.82); people searched under OU=people,
             every enabled person admitted (2.1.6.83: who may do what is the groups', and the grants'); writable, so
             a password changed at sign-in lands in AD. fabric creates people itself (directory/create_person):
             Keycloak does not. With kerberos it also accepts a domain logon's ticket (SPNEGO, manual 2.3.6.2.6.2)
             with the site's fabric-sso keytab; any of the keytab's principals (HTTP/sso.<domain>,
             HTTP/<host>.<domain>); passwords are still checked over LDAP.
    Inputs:  kc — Admin; realm — realm name; realm_id — parent id from ensure_realm; v — vars (ad_base_dn, dc_name,
             host_ip); s — secrets (ad_keycloak_password); writable —
             False makes it READ_ONLY; kerberos — accept Kerberos tickets (the keytab is in place).
    Returns: str, the federation component id. An existing AD provider is updated in place (fabric's settings win,
             other settings kept); a provider of another kind (an older install's) is removed first and made anew, so
             Keycloak creates AD's own mappers (account controls, pwdLastSet) with it.
    Fails:   SystemExit from Admin.call; KeyError if a needed var or secret is missing; StopIteration if a created
             provider cannot be found again.
    Feeds:   configure_keycloak (the id is passed to ensure_group_mapper)."""
    base = v["ad_base_dn"]
    admitted = f"(!(userAccountControl:{MATCH_BIT}:={ACCOUNTDISABLE}))"     # every enabled person (2.1.6.83)
    config = {
        "enabled": ["true"],
        "vendor": ["ad"],
        "editMode": ["WRITABLE" if writable else "READ_ONLY"],
        "syncRegistrations": ["false"],
        "importEnabled": ["true"],
        "usernameLDAPAttribute": ["sAMAccountName"],
        "rdnLDAPAttribute": ["cn"],
        "uuidLDAPAttribute": ["objectGUID"],
        "userObjectClasses": ["person, organizationalPerson, user"],
        # the DC on fabric_net's gateway: the traffic stays on the bridge (2.1.2.15)
        "connectionUrl": [f"ldaps://{v.get('ip_fabric_gateway', '10.255.0.1')}:636"],
        "usersDn": [f"OU=people,{base}"],
        "searchScope": ["2"],
        "customUserSearchFilter": [admitted],
        "authType": ["simple"],
        "bindDn": [f"CN=fabric-keycloak-{v['dc_name']},OU=service-accounts,{base}"],
        "bindCredential": [s["ad_keycloak_password"]],
        "useTruststoreSpi": ["always"],
        "startTls": ["false"],
        "connectionPooling": ["true"],
        "pagination": ["true"],
        "usePasswordModifyExtendedOp": ["false"],
        "trustEmail": ["true"],
        "batchSizeForSync": ["1000"],
        "allowKerberosAuthentication": ["true" if kerberos else "false"],
        "useKerberosForPasswordAuthentication": ["false"],
    }
    if kerberos:
        config.update({"kerberosRealm": [v["ad_domain"].upper()], "serverPrincipal": ["*"], "keyTab": [KEYTAB]})
    path = f"/{q(realm)}/components?type={q(USER_STORAGE)}"
    ldap = next((c for c in kc.call("GET", path)[1] if c.get("providerId") == "ldap"), None)
    if ldap is not None and (ldap.get("config", {}).get("vendor") or [""])[0] != "ad":
        kc.call("DELETE", f"/{q(realm)}/components/{ldap['id']}")
        step(f"removed the LDAP federation {ldap.get('name')} (fabric's directory is Samba AD)")
        ldap = None
    if ldap is None:
        kc.call("POST", f"/{q(realm)}/components", {
            "name": NAME, "providerId": "ldap", "providerType": USER_STORAGE, "parentId": realm_id, "config": config})
        ldap = next(c for c in kc.call("GET", path)[1] if c.get("providerId") == "ldap")
        step(f"created LDAP federation ({NAME})")
    else:
        ldap["name"] = NAME
        ldap["config"] = {**ldap.get("config", {}), **config}
        kc.call("PUT", f"/{q(realm)}/components/{ldap['id']}", ldap)
        step(f"updated LDAP federation {ldap['id']} -> {config['connectionUrl'][0]}")
    return ldap["id"]
