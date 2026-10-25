"""fabric policy's connection to the site's domain controller (manual 1.6.3.11): verified LDAPS to the host's
address, as the DC's read-only `fabric-radius-<dc>` (2.1.6.82; one connection per FreeRADIUS thread), or as a person
to check their password."""
import json
import threading

import ldap

CONFIG = "/etc/freeradius/fabric/fabric-radius.json"
_local = threading.local()
_conf = {}


def load_config():
    """Purpose: load the policy's settings once per process: fabric-radius.json and the read account's password.
    Inputs:  none. Reads /etc/freeradius/fabric/fabric-radius.json and the file its "password_file" names.
    Returns: dict (cached module-level): uri, ca_file, bind_dn (the account's user principal name), base (the
             domain's DN), site, people, password_file, password.
    Fails:   OSError if a file is missing or unreadable; json.JSONDecodeError; KeyError without "password_file".
    Feeds:   connect, check_person, lookup_device."""
    if not _conf:
        with open(CONFIG) as f:
            _conf.update(json.load(f))
        with open(_conf["password_file"]) as f:
            _conf["password"] = f.read().strip()
    return _conf


def folder_dn(conf, name):
    """Purpose: one of the domain's folders (manual 1.6.13.2): OU=people, OU=machines, OU=groups, OU=devices,
             OU=device-roles; one set for the whole domain (2.1.6.80).
    Inputs:  conf — load_config()'s dict; name — the folder's name.
    Returns: str, e.g. "OU=devices,<domain>".
    Fails:   KeyError without "base".
    Feeds:   check_person, check_peap, lookup_device."""
    return f"OU={name},{conf['base']}"


def connect(dn=None, password=None):
    """Purpose: open a verified LDAPS connection to the DC and bind, with short timeouts so a switch still gets an
             answer when the directory is down.
    Inputs:  dn — str, bind as this DN (a person) with `password`; None (default) binds as the read account
             (conf bind_dn and its password file).
    Returns: a bound python-ldap LDAPObject.
    Fails:   ldap.INVALID_CREDENTIALS (a wrong password, or a locked, disabled or expired account: AD answers all
             of them so), ldap.SERVER_DOWN, ldap.TIMEOUT and other ldap.LDAPError from the bind; load_config errors.
    Feeds:   search (reader connection per thread), check_person (bind as the person)."""
    conf = load_config()
    c = ldap.initialize(conf["uri"])
    c.set_option(ldap.OPT_X_TLS_CACERTFILE, conf["ca_file"])
    c.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    c.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    # short: a switch waits a few seconds; the directory down must still answer Reject in time
    c.set_option(ldap.OPT_NETWORK_TIMEOUT, 2)
    c.set_option(ldap.OPT_TIMEOUT, 3)
    c.set_option(ldap.OPT_REFERRALS, 0)       # AD's referrals to its partitions are never followed
    c.simple_bind_s(dn or conf["bind_dn"], conf["password"] if dn is None else password)
    return c


def search(base, filterstr, attrs, subtree=False):
    """Purpose: one search on this thread's reader connection; reconnects once if the DC restarted since.
    Inputs:  base — str DN; filterstr — str LDAP filter (callers escape values); attrs — list of attribute names;
             subtree — bool: the whole subtree (default: base's direct children).
    Returns: list of (dn, {attr: [bytes]}) that match; AD's search references are left out.
    Fails:   ldap.SERVER_DOWN / CONNECT_ERROR / TIMEOUT on the second attempt; any other LDAP error at once
             (the caller refuses).
    Feeds:   check_person, lookup_device."""
    scope = ldap.SCOPE_SUBTREE if subtree else ldap.SCOPE_ONELEVEL
    for attempt in (1, 2):
        c = getattr(_local, "conn", None)
        try:
            if c is None:
                c = _local.conn = connect()
            return [(dn, a) for dn, a in c.search_s(base, scope, filterstr, attrs) if dn]
        except (ldap.SERVER_DOWN, ldap.CONNECT_ERROR, ldap.TIMEOUT):
            _local.conn = None
            if attempt == 2:
                raise
