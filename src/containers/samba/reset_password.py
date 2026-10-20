import ldb

from find_person import find_person


def reset_password(samdb, lp, site, uid, password):
    """Purpose: a person's sign-in reset in the directory (manual 1.6.3.8): a new one-time password they must change
             at their next sign-in, and their account unlocked.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); uid — the user name;
             password — the one-time password (satisfies the policy).
    Returns: {"uid"}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT for no such person in OU=people; ERR_INSUFFICIENT_ACCESS_RIGHTS when AD
             refuses the agent; ERR_CONSTRAINT_VIOLATION when the policy refuses the password.
    Feeds:   directory_ops (op "reset_password")."""
    p = find_person(samdb, uid)
    samdb.setpassword(f"(sAMAccountName={ldb.binary_encode(uid)})", password, force_change_at_next_login=True)
    if int(str(p.get("lockoutTime", ["0"])[0])):
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": str(p.dn), "lockoutTime": "0"}, ldb.FLAG_MOD_REPLACE))
    return {"uid": uid}
