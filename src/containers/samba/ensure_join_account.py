import time

import ldb

LIFETIME = 3600          # seconds: a join account is good for one hour (manual 1.9.8.4)
SETTLE = 60              # seconds a site DC may take to replicate a sibling join account's deletion (2.3.6.27)


def _filetime(epoch):
    """Purpose: an AD timestamp (100 ns since 1601) for a time.
    Inputs:  epoch — seconds since 1970.
    Returns: str.
    Fails:   never.
    Feeds:   ensure_join_account."""
    return str(int((epoch + 11644473600) * 10_000_000))


def _add_to_domain_admins(samdb, name, settle=SETTLE, pause=2.0, sleep=time.sleep, clock=time.monotonic):
    """Purpose: the join account made a member of Domain Admins, waiting out a sibling's deletion still replicating
             (2.3.6.27): at a site's DC (a nested join), another site's join account the root deleted moments ago
             can still stand in Domain Admins' members while its deletion replicates, and AD then refuses the change
             naming that account ("No such Base DN: CN=fabric-join-<other>,..."). Asked again every `pause`
             seconds until it goes through, for at most `settle`; any other refusal at once.
    Inputs:  samdb — SamDB; name — the join account's sAMAccountName; settle, pause — seconds; sleep, clock —
             time.sleep and time.monotonic (tests give their own).
    Returns: None.
    Fails:   ldb.LdbError: any refusal but a missing object; a missing object that is this account itself; one that
             outlasts `settle` (its message then says the deletion did not replicate in time).
    Feeds:   ensure_join_account."""
    deadline = clock() + settle
    while True:
        try:
            samdb.add_remove_group_members("Domain Admins", [name], add_members_operation=True)
            return
        except ldb.LdbError as e:
            code, text = e.args[0], str(e.args[1] if len(e.args) > 1 else "")
            if code != ldb.ERR_NO_SUCH_OBJECT or f"CN={name}," in text:
                raise
            if clock() >= deadline:
                raise ldb.LdbError(code, f"{text} (another join account's deletion did not replicate within "
                                         f"{settle} s: join again in a minute)")
            sleep(pause)


def ensure_join_account(samdb, name, password):
    """Purpose: the temporary account a new site's DC joins the domain with (manual 1.9.8.4, S8.1): a member of
             Domain Admins (Samba's DC join needs it), expiring one hour from now; the site deletes it once joined.
             Made again (password and expiry renewed) if the join is retried.
    Inputs:  samdb — SamDB (as the system, at the root); name — sAMAccountName (fabric-join-<site>); password — str.
    Returns: list of str, what changed.
    Fails:   ldb.LdbError for a change AD refuses (e.g. a password the policy refuses).
    Feeds:   converge (state join_account)."""
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectClass=user)(sAMAccountName={ldb.binary_encode(name)}))", attrs=["dn"])
    if found:
        samdb.setpassword(f"(sAMAccountName={ldb.binary_encode(name)})", password, force_change_at_next_login=False)
        dn, done = found[0].dn, f"join account {name}: renewed"
    else:
        samdb.newuser(name, password, force_password_change_at_next_login_req=False)
        dn = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                          expression=f"(sAMAccountName={ldb.binary_encode(name)})", attrs=["dn"])[0].dn
        _add_to_domain_admins(samdb, name)
        done = f"join account {name}: created"
    msg = ldb.Message(dn)
    msg["accountExpires"] = ldb.MessageElement([_filetime(time.time() + LIFETIME)], ldb.FLAG_MOD_REPLACE,
                                               "accountExpires")
    samdb.modify(msg)
    return [done]
