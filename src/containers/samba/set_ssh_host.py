import re

import ldb

from find_machine import find_machine
from list_ssh_hosts import AUX

# one OpenSSH key or certificate line, without its comment: "<type> <base64>"
LINE = re.compile(r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))(-cert-v01@openssh\.com)? [A-Za-z0-9+/]+={0,2}$")
MOST = 6                              # values per attribute: one key or certificate per family, with room to spare


def _lines(values, cert):
    """Purpose: the values to store, each checked to be one key (cert False) or one certificate (cert True) line.
    Inputs:  values — list of str; cert — bool.
    Returns: list of str, stripped, each once, in order.
    Fails:   ValueError naming the first value that is not one, or more than MOST.
    Feeds:   set_ssh_host."""
    out = []
    for v in values:
        v = " ".join(str(v).split()[:2])
        if not LINE.match(v) or ("-cert-v01@" in v) != cert or len(v) > 16384:
            raise ValueError(f"not one SSH {'certificate' if cert else 'public key'}: {v[:40]!r}")
        if v not in out:
            out.append(v)
    if len(out) > MOST:
        raise ValueError(f"at most {MOST} SSH {'certificates' if cert else 'keys'} per machine")
    return out


def set_ssh_host(samdb, lp, site, name, certs=None, keys=None):
    """Purpose: write a machine's SSH host certificates (fabricSshHostCert, written by fabric only: manual
             1.6.11.9.8) and, for the fabric host, which publishes as the site's agent, its host keys
             (fabricSshHostKey); the auxiliary class fabricSshHost added first when missing. An empty list removes
             the attribute; None leaves it.
    Inputs:  samdb — SamDB (as the site's agent); lp — LoadParm (unused); site — str; name — the machine's name
             (any case); certs, keys — lists of lines, or None.
    Returns: {"name", "changed": bool}.
    Fails:   ValueError (kind "invalid") for a value that is not a key or certificate line; ldb.LdbError
             ERR_NO_SUCH_OBJECT (no such machine in the site), ERR_INSUFFICIENT_ACCESS_RIGHTS.
    Feeds:   directory_ops (op "set_ssh_host") <- vault/ssh/sign_ssh_hosts."""
    want = {}
    if certs is not None:
        want["fabricSshHostCert"] = _lines(certs, True)
    if keys is not None:
        want["fabricSshHostKey"] = _lines(keys, False)
    dn = str(find_machine(samdb, site, name).dn)
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["objectClass", *want])[0]
    changed = False
    if AUX not in [str(c) for c in have.get("objectClass", [])]:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": AUX}, ldb.FLAG_MOD_ADD))
        changed = True
    for attr, values in want.items():
        if sorted(str(x) for x in have.get(attr, [])) == sorted(values):
            continue
        msg = ldb.Message(ldb.Dn(samdb, dn))
        msg[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
        samdb.modify(msg)
        changed = True
    return {"name": name.lower(), "changed": changed}
