import os
import secrets
import subprocess

import ldb

import paths

KEYTAB = "/data/sso.keytab"              # the host copies it to Keycloak (fabriclib/keycloak/install_sso_keytab)
AES_ONLY = "24"                          # msDS-SupportedEncryptionTypes: AES128 | AES256 (Java refuses RC4 tickets)
DONT_EXPIRE_PASSWORD = 0x10000


def _export(conf, realm, spns):
    """Purpose: the keytab of the SSO account's principals, written to KEYTAB (0600) through a file beside it.
    Inputs:  conf — smb.conf path; realm — the AD realm (upper case); spns — list of SPNs.
    Returns: None.
    Fails:   CalledProcessError from samba-tool; OSError.
    Feeds:   ensure_sso_account."""
    new = KEYTAB + ".new"
    if os.path.exists(new):
        os.remove(new)
    for spn in spns:
        subprocess.run(["samba-tool", "domain", "exportkeytab", new, f"--principal={spn}@{realm}", "-s", conf],
                       check=True, capture_output=True)
    os.chmod(new, 0o600)
    os.replace(new, KEYTAB)


def ensure_sso_account(samdb, lp, conf, site, spns):
    """Purpose: the site's Kerberos sign-in account for Keycloak (manual 2.3.6.2.6.2): fabric-sso-<site> in the
             domain's OU=service-accounts (1.6.13.2; one per site, as Keycloak is), holding exactly the given HTTP
             SPNs, AES keys only, its password random and never leaving the DC (nothing signs in with it: Keycloak
             only decrypts tickets with its keytab); the keytab exported to /data/sso.keytab when the account, its SPNs
             or its key types change, or the keytab is missing.
    Inputs:  samdb — SamDB (system); lp — LoadParm (the realm); conf — smb.conf path (samba-tool); site — str;
             spns — list of "HTTP/<name>" ([] = no Kerberos sign-in at this site: nothing is done).
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (e.g. an SPN another account holds); CalledProcessError from
             samba-tool; OSError writing the keytab.
    Feeds:   converge (state sso_spns)."""
    if not spns:
        return []
    name, done = f"fabric-sso-{site}", []
    expr = f"(sAMAccountName={ldb.binary_encode(name)})"
    attrs = ["userAccountControl", "servicePrincipalName", "msDS-SupportedEncryptionTypes"]
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, expression=expr, attrs=attrs)
    if not found:
        services = paths.relative(samdb, paths.folder_dn(samdb, "service-accounts"))
        # a random password that meets any complexity policy; it is never stored or shown
        samdb.newuser(name, secrets.token_urlsafe(32) + "aA1!", userou=services,
                      force_password_change_at_next_login_req=False)
        found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, expression=expr, attrs=attrs)
        done.append(f"Kerberos sign-in account {name} created")
    entry = found[0]
    want = {"servicePrincipalName": sorted(spns), "msDS-SupportedEncryptionTypes": [AES_ONLY],
            "userAccountControl": [str(int(str(entry["userAccountControl"][0])) | DONT_EXPIRE_PASSWORD)]}
    msg = ldb.Message(entry.dn)
    for attr, values in want.items():
        have = sorted(str(x) for x in entry.get(attr, []))
        if have != values:
            msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
            if attr != "userAccountControl":
                done.append(f"{name}: {attr} set")
    if len(msg) > 0:
        samdb.modify(msg)
    if done or not os.path.exists(KEYTAB):
        _export(conf, lp.get("realm").upper(), spns)
        done.append(f"{name}: keytab exported")
    return done
