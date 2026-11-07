import ldb

SERVER_TRUST, PARTIAL_SECRETS = 0x2000, 0x4000000     # userAccountControl: a DC, a read-only DC


def all_machines(samdb, expression="", attrs=()):
    """Purpose: the domain's machines wherever they are (1.8.8.5: any machine may be moved to any OU): every computer
             account in an OU of the domain, OU=machines and its type OUs, OU=fabric-hosts and an admin's own OUs
             alike; never a domain controller (by its account's flags or the Domain Controllers OU) nor an account in
             one of AD's own containers (CN=Computers: fabric redirects new computers to OU=machines, 1.6.13.2).
    Inputs:  samdb — SamDB; expression — an LDAP filter the computers must also match ("" for all); attrs — the
             attributes wanted (userAccountControl is always read).
    Returns: list of ldb.Message.
    Fails:   ldb.LdbError from the search.
    Feeds:   find_machine, list_machines."""
    want = sorted(set(attrs) | {"userAccountControl"})
    found = samdb.search(base=str(samdb.domain_dn()), scope=ldb.SCOPE_SUBTREE,
                         expression=f"(&(objectCategory=computer){expression})", attrs=want)
    dcs = f"ou=domain controllers,{samdb.domain_dn()}".lower()
    out = []
    for m in found:
        dn = str(m.dn)
        parent = dn.split(",", 1)[1]
        if int(str(m.get("userAccountControl", [0])[0])) & (SERVER_TRUST | PARTIAL_SECRETS):
            continue
        if not parent.upper().startswith("OU=") or parent.lower() == dcs:
            continue
        out.append(m)
    return out
