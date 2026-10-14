import ldb

import paths

RDN = "CN=fabric-ssh-cas"
KEYWORD = "fabric-ssh-cas"
_KEY = ("ssh-ed25519 ", "ecdsa-sha2-nistp256 ", "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 ", "ssh-rsa ")


def set_ssh_cas(samdb, lp, site, user_ca="", host_ca="", domain=""):
    """Purpose: publish this site's SSH CAs to the organisation (decision 2.1.7.14, manual 1.6.11.9.16): a
             serviceConnectionPoint `CN=fabric-ssh-cas` in the site's own OU (no schema change), its
             serviceBindingInformation `user <key>`, `host <key>`, `domain <domain>`; with neither key (SSH
             certificates off) the object is removed. Only public keys travel. Idempotent.
    Inputs:  samdb — SamDB (as the site's agent: its rights are on its own OU); lp — unused; site — str (this site:
             the object goes in its OU only); user_ca, host_ca — public key lines or ""; domain — this site's DNS
             domain.
    Returns: {"changed": bool, "dn"}.
    Fails:   ValueError for a key that is not an SSH public key line or a domain with spaces (kind "invalid");
             ldb.LdbError from a change AD refuses.
    Feeds:   directory_ops (op "set_ssh_cas") <- vault/ssh/sign_ssh_hosts."""
    values = []
    for kind, key in (("user", user_ca), ("host", host_ca)):
        key = " ".join(str(key or "").split()[:2])
        if key:
            if not key.startswith(_KEY) or len(key.split()) != 2:
                raise ValueError(f"the {kind} CA is not an SSH public key")
            values.append(f"{kind} {key}")
    domain = str(domain or "").strip().lower()
    if domain and (" " in domain or len(domain) > 253):
        raise ValueError("the domain is not valid")
    dn = f"{RDN},{paths.site_dn(samdb, site)}"
    try:
        have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["serviceBindingInformation"])[0]
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_NO_SUCH_OBJECT:
            raise
        have = None
    if not values:
        if have is None:
            return {"changed": False, "dn": dn}
        samdb.delete(dn)
        return {"changed": True, "dn": dn}
    if domain:
        values.append(f"domain {domain}")
    if have is None:
        samdb.add({"dn": dn, "objectClass": "serviceConnectionPoint", "keywords": [KEYWORD, f"site={site}"],
                   "serviceBindingInformation": values})
        return {"changed": True, "dn": dn}
    if sorted(str(x) for x in have.get("serviceBindingInformation", [])) == sorted(values):
        return {"changed": False, "dn": dn}
    samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "serviceBindingInformation": values}, ldb.FLAG_MOD_REPLACE))
    return {"changed": True, "dn": dn}
