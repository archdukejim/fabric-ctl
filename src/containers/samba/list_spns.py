import ldb


def list_spns(samdb, lp, site):
    """Purpose: the domain's service principals (manual 1.6.12.9), read-only: every SPN of every computer and service
             account, with the account it is on; one held by two accounts (which breaks Kerberos for both) is flagged
             with both. AD compares SPNs without regard to case, and so does this.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused: the domain's).
    Returns: {"spns": [{"spn", "account", "kind": "computer"|"account", "duplicate": bool}], "duplicates": [spn]},
             by SPN.
    Fails:   ldb.LdbError from the search.
    Feeds:   directory_ops (op "list_spns")."""
    rows, seen = [], {}
    for m in samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                          expression="(&(objectClass=user)(servicePrincipalName=*))",
                          attrs=["sAMAccountName", "servicePrincipalName", "objectClass"]):
        kind = "computer" if "computer" in {str(c).lower() for c in m.get("objectClass", [])} else "account"
        account = str(m["sAMAccountName"][0])
        for spn in m.get("servicePrincipalName", []):
            spn = str(spn)
            rows.append({"spn": spn, "account": account, "kind": kind})
            seen.setdefault(spn.lower(), set()).add(account.lower())
    dupes = {s for s, holders in seen.items() if len(holders) > 1}
    for r in rows:
        r["duplicate"] = r["spn"].lower() in dupes
    return {"spns": sorted(rows, key=lambda r: (r["spn"].lower(), r["account"].lower())),
            "duplicates": sorted({r["spn"] for r in rows if r["duplicate"]}, key=str.lower)}
