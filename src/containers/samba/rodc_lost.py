"""A lost or stolen read-only DC (decision 2.1.6.58, manual 1.9.8.21): run at a writable DC, as the system, on its own
database — the accounts whose passwords the read-only DC held, their passwords replaced, the DC's objects removed.
    docker exec -i samba python3 /fabric/rodc_lost.py < request.json
The request on stdin: {"action": "list", "site"} | {"action": "reset", "site", "accounts": [{"dn", "kind"}]} |
{"action": "remove", "site", "name"}. Prints one JSON object: the action's result, or {"error": why} (exit 1)."""
import json
import logging
import secrets
import string
import sys

import ldb

from open_samdb import open_samdb

CONF = "/data/etc/smb.conf"
PARTIAL_SECRETS_ACCOUNT = 0x04000000    # userAccountControl: a read-only DC's account
KINDS = ("person", "machine", "service")


def _dn_of(value):
    """Purpose: the DN in a DN-Binary or DN-String value ("B:<n>:<hex>:<DN>", "S:<n>:<text>:<DN>"), or the value
             itself when it is a plain DN.
    Inputs:  value — str.
    Returns: str.
    Fails:   never.
    Feeds:   _rodcs."""
    if value[:2] in ("B:", "S:") and value.count(":") >= 3:
        return value.split(":", 3)[3]
    return value


def _rodcs(samdb, site):
    """Purpose: the read-only DCs of an AD site: its server objects (`CN=<site>,CN=Sites`) whose computer account is
             a read-only DC's, with what each was told (msDS-RevealedUsers, AD's record of every account whose secrets
             were sent to it; msDS-RevealedList too where the DC constructs it).
    Inputs:  samdb — SamDB (system); site — the AD site's name.
    Returns: list of {"name", "dn" (computer account), "krbtgt" (its own krbtgt account's DN, or ""), "revealed":
             [DN], sorted, each once}.
    Fails:   ldb.LdbError from a search.
    Feeds:   rodc_lost."""
    base = f"CN=Sites,{samdb.get_config_basedn()}"
    found = samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL,
                         expression=f"(&(objectClass=site)(cn={ldb.binary_encode(site)}))", attrs=["cn"])
    out = []
    for s in found:
        for srv in samdb.search(base=str(s.dn), scope=ldb.SCOPE_SUBTREE, expression="(objectClass=server)",
                                attrs=["cn", "serverReference"]):
            if "serverReference" not in srv:
                continue
            try:
                acct = samdb.search(base=str(srv["serverReference"][0]), scope=ldb.SCOPE_BASE,
                                    attrs=["userAccountControl", "msDS-KrbTgtLink", "msDS-RevealedUsers",
                                           "msDS-RevealedList"])[0]
            except ldb.LdbError:
                continue
            if not int(str(acct.get("userAccountControl", ["0"])[0])) & PARTIAL_SECRETS_ACCOUNT:
                continue
            revealed = {_dn_of(str(x)).lower(): _dn_of(str(x)) for attr in ("msDS-RevealedUsers", "msDS-RevealedList")
                        for x in acct.get(attr, [])}
            out.append({"name": str(srv["cn"][0]), "dn": str(acct.dn),
                        "krbtgt": str(acct["msDS-KrbTgtLink"][0]) if "msDS-KrbTgtLink" in acct else "",
                        "revealed": [revealed[k] for k in sorted(revealed)]})
    return out


def _account(samdb, dn, rodc):
    """Purpose: one revealed account and what kind it is: the read-only DC's own account and its krbtgt (removed with
             the DC, never reset), the domain's krbtgt (never touched here), a machine, a service account (a site's
             OU=service-accounts, or a password that never expires), or a person.
    Inputs:  samdb — SamDB; dn — the account's DN; rodc — the DC's _rodcs entry.
    Returns: {"dn", "name" (sAMAccountName), "kind": person|machine|service|dc|krbtgt|protected|gone}.
    Fails:   ldb.LdbError other than no such object.
    Feeds:   rodc_lost (list)."""
    if dn.lower() == rodc["dn"].lower():
        return {"dn": dn, "name": rodc["name"] + "$", "kind": "dc"}
    if rodc["krbtgt"] and dn.lower() == rodc["krbtgt"].lower():
        return {"dn": dn, "name": "", "kind": "krbtgt"}
    try:
        obj = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                           attrs=["objectClass", "sAMAccountName", "userAccountControl"])[0]
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return {"dn": dn, "name": "", "kind": "gone"}
        raise
    name = str(obj.get("sAMAccountName", [""])[0])
    classes = [str(c).lower() for c in obj.get("objectClass", [])]
    uac = int(str(obj.get("userAccountControl", ["0"])[0]))
    if name.lower() == "krbtgt" or name.lower().startswith("krbtgt_"):
        kind = "protected"
    elif "computer" in classes:
        kind = "machine"
    elif ",ou=service-accounts," in dn.lower() or uac & 0x10000:
        kind = "service"
    else:
        kind = "person"
    return {"dn": str(obj.dn), "name": name, "kind": kind}


def _password():
    """Purpose: a random password nobody is told: 32 characters from every class AD's complexity rule counts.
    Inputs:  none.
    Returns: str.
    Fails:   never.
    Feeds:   rodc_lost (reset)."""
    pick = string.ascii_letters + string.digits + "-_.!"
    return "".join(secrets.choice(pick) for _ in range(28)) + "aA1!"


def rodc_lost(request):
    """Purpose: one step of handling a lost read-only DC (decision 2.1.6.58, manual 1.9.8.21), on this writable DC's
             own database as the system: list — the site's read-only DCs and every account each was told the
             password of, with its kind; reset — each account given replaced (people: a random password and change at
             next sign-in; machines and service accounts: a random password), only when the account is in a read-only
             DC's revealed list now (or the DC is gone already: the caller's record holds the list); remove — the DC
             removed as Samba removes a dead DC (`samba-tool domain demote --remove-other-dead-server`: its server and
             NTDS settings, its computer account with its password replication allow list, its own krbtgt account,
             its DNS records), the allow list cleared first.
    Inputs:  request — dict as the module docstring says.
    Returns: list: {"rodcs": [{"name", "dn", "krbtgt", "accounts": [{"dn", "name", "kind"}]}]}; reset: {"reset":
             [{"dn", "kind"}]}; remove: {"removed": bool (False: nothing of it was left)}.
    Fails:   ValueError: this DC is read-only; an unknown action; an account to reset that no read-only DC of the site
             holds while one exists, or a kind that is not person, machine or service; ldb.LdbError.
    Feeds:   this script's main <- fabriclib/samba/run_rodc_lost."""
    samdb, _ = open_samdb(CONF)
    if samdb.am_rodc():
        raise ValueError("this domain controller is read-only: run at a writable one")
    action, site = request.get("action"), str(request.get("site") or "")
    rodcs = _rodcs(samdb, site)
    if action == "list":
        return {"rodcs": [{"name": r["name"], "dn": r["dn"], "krbtgt": r["krbtgt"],
                           "accounts": [_account(samdb, dn, r) for dn in r["revealed"]]} for r in rodcs]}
    if action == "reset":
        held = {dn.lower() for r in rodcs for dn in r["revealed"]}
        done = []
        for a in request.get("accounts") or []:
            dn, kind = str(a.get("dn") or ""), a.get("kind")
            if kind not in KINDS:
                raise ValueError(f"{dn}: only people, machines and service accounts are reset ({kind})")
            if rodcs and dn.lower() not in held:
                raise ValueError(f"{dn} is not in the read-only DC's revealed list: it is never reset here")
            samdb.setpassword(f"(distinguishedName={ldb.binary_encode(dn)})", _password(),
                              force_change_at_next_login=(kind == "person"))
            done.append({"dn": dn, "kind": kind})
        return {"reset": done}
    if action == "remove":
        from samba.remove_dc import remove_dc            # Samba's own removal of a dead DC
        name = str(request.get("name") or "")
        match = [r for r in rodcs if r["name"].lower() == name.lower()]
        if not match:
            return {"removed": False}
        try:
            msg = ldb.Message(ldb.Dn(samdb, match[0]["dn"]))
            msg["msDS-RevealOnDemandGroup"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "msDS-RevealOnDemandGroup")
            samdb.modify(msg)
        except ldb.LdbError as e:
            if e.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise
        remove_dc(samdb, logging.getLogger("rodc_lost"), match[0]["name"])
        return {"removed": True}
    raise ValueError(f"unknown action {action!r}")


if __name__ == "__main__":
    try:
        print(json.dumps(rodc_lost(json.load(sys.stdin))))
    except Exception as e:                  # reported by the caller
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        sys.exit(1)
