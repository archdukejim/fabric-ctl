"""A person's own password change (manual 1.8.6.6, 2.1.1.62), inside the DC, signed in over LDAP as the person with
their current password, never as fabric's account or the system: AD checks the current password and the domain's
policy as it does for Windows' own change.
    docker exec -i samba python3 /fabric/change_own_password.py < request.json
The request on stdin (never a command line: it holds both passwords): {"uid", "current", "new"}. Prints one JSON
object: {"result": {"uid", "changed": true}} or {"error": message, "kind": "wrong"|"policy"|"other"} (exit 0 either
way)."""
import json
import sys

import ldb
from samba.credentials import DONT_USE_KERBEROS, Credentials
from samba.param import LoadParm
from samba.samdb import SamDB

CONF = "/data/etc/smb.conf"


def _quoted(password):
    """Purpose: a password as AD's unicodePwd takes it: in double quotes, UTF-16-LE.
    Inputs:  password — str.
    Returns: bytes.
    Fails:   never.
    Feeds:   change_own_password."""
    return f'"{password}"'.encode("utf-16-le")


def change_own_password(uid, current, new):
    """Purpose: the change itself: an LDAP bind as the person (NTLM, signed and sealed on loopback), then one modify
             that deletes the current unicodePwd and adds the new one, AD's user-initiated change (it checks the
             current password, the history, the minimum age and the policy).
    Inputs:  uid — the user name; current — their current password; new — the new one.
    Returns: {"result": {"uid", "changed": True}} or {"error", "kind"}: "wrong" (the current password, or an account
             that may not sign in: disabled, locked, expired), "policy" (the new one refused by the domain's policy:
             length, complexity, history, minimum age), "other".
    Fails:   never: errors become the answer.
    Feeds:   this script's main."""
    lp = LoadParm()
    lp.load(CONF)
    creds = Credentials()
    creds.guess(lp)
    creds.set_username(uid)
    creds.set_password(current)
    creds.set_domain(lp.get("workgroup"))
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    try:
        samdb = SamDB(url="ldap://127.0.0.1", credentials=creds, lp=lp)
    except ldb.LdbError:
        return {"error": "the current password is wrong, or the account may not sign in (disabled, locked out or "
                         "expired)", "kind": "wrong"}
    try:
        found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE, attrs=["dn"],
                             expression=f"(&(objectClass=user)(!(objectClass=computer))"
                                        f"(sAMAccountName={ldb.binary_encode(uid)}))")
        if not found:
            return {"error": f"no person {uid}", "kind": "other"}
        msg = ldb.Message(found[0].dn)
        msg["old"] = ldb.MessageElement(_quoted(current), ldb.FLAG_MOD_DELETE, "unicodePwd")
        msg["new"] = ldb.MessageElement(_quoted(new), ldb.FLAG_MOD_ADD, "unicodePwd")
        samdb.modify(msg)
    except ldb.LdbError as e:
        code, text = e.args[0], (e.args[1] if len(e.args) > 1 else str(e))
        if code == ldb.ERR_CONSTRAINT_VIOLATION:
            return {"error": "the domain's password policy refused the new password (its length, complexity, "
                             "history or minimum age)", "kind": "policy"}
        return {"error": f"the directory refused it: {text}", "kind": "other"}
    return {"result": {"uid": uid, "changed": True}}


if __name__ == "__main__":
    req = json.load(sys.stdin)
    print(json.dumps(change_own_password(str(req.get("uid", "")), str(req.get("current", "")),
                                         str(req.get("new", "")))))
