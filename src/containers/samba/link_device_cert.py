import ldb

import paths


def link_device_cert(samdb, lp, site, name, fingerprint, link):
    """Purpose: a certificate's SHA-256 fingerprint recorded on (or removed from) a device, so 802.1X EAP-TLS can tell
             which device a certificate belongs to; idempotent.
    Inputs:  samdb — SamDB (as the DC's agent); lp — LoadParm (unused); site — str (unused); name — the device's name;
             fingerprint — "AA:BB:…" (checked by fabric); link — bool: record, else remove.
    Returns: {"changed": bool}.
    Fails:   ldb.LdbError ERR_NO_SUCH_OBJECT for no such device, ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "link_device_cert")."""
    dn = f"CN={name},{paths.folder_dn(samdb, 'devices')}"
    have = [str(x) for x in samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                                         attrs=["fabricCertFingerprint"])[0].get("fabricCertFingerprint", [])]
    if (fingerprint in have) == bool(link):
        return {"changed": False}
    flag = ldb.FLAG_MOD_ADD if link else ldb.FLAG_MOD_DELETE
    msg = ldb.Message(ldb.Dn(samdb, dn))
    msg["fabricCertFingerprint"] = ldb.MessageElement([fingerprint], flag, "fabricCertFingerprint")
    samdb.modify(msg)
    return {"changed": True}
