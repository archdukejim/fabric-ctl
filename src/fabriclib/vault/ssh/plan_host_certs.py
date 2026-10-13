from fabriclib.common.errors import ValidationError
from fabriclib.vault.ssh.constants import HOST_KEY_TYPES, RENEW_DAYS
from fabriclib.vault.ssh.parse_ssh_cert import parse_ssh_cert
from fabriclib.vault.ssh.parse_ssh_key import parse_ssh_key

SKEW = 300          # seconds a certificate may start in the future (the clocks of the DC and OpenBao)


def _family(kind):
    """Purpose: a host key's family: sshd uses one host key of each.
    Inputs:  kind — an OpenSSH key type.
    Returns: "ed25519", "ecdsa" or "rsa".
    Fails:   never.
    Feeds:   plan_host_certs."""
    return "ecdsa" if kind.startswith("ecdsa") else kind.replace("ssh-", "")


def plan_host_certs(keys, certs, principals, ca_fingerprint, now):
    """Purpose: what one machine's host certificates need (manual 1.6.11.9.8): each host key it published, judged as a
             user key is (Ed25519, ECDSA, RSA of 3072 bits or more; one key per family, the first kept), keeps the
             certificate it has when that one certifies that key, is a host certificate signed by today's host CA,
             names exactly the principals fabric gives the machine, has begun and has more than RENEW_DAYS left;
             otherwise the key is signed again. Certificates of keys no longer published are dropped.
    Inputs:  keys — list of str, the machine's fabricSshHostKey values; certs — list of str, its fabricSshHostCert
             values; principals — list of str (host_principals); ca_fingerprint — the host CA's "SHA256:…";
             now — int, seconds since 1970 UTC.
    Returns: {"keep": [certificate lines kept], "sign": [key lines to sign, "<type> <base64>"],
             "refused": [(the key's first 40 characters, why)], "changed": bool (the certificates will change)}.
    Fails:   never: a key or certificate that does not parse is refused or dropped, never raised.
    Feeds:   vault/ssh/sign_ssh_hosts."""
    want = sorted(principals)
    by_key = {}
    for text in certs:
        try:
            c = parse_ssh_cert(text)
        except ValidationError:
            continue
        good = (c["kind"] == "host" and c["ca_fingerprint"] == ca_fingerprint and sorted(c["principals"]) == want
                and c["valid_after"] <= now + SKEW and c["valid_before"] - now > RENEW_DAYS * 86400)
        if good:
            by_key[c["key_fingerprint"]] = c["line"]
    keep, sign, refused, families = [], [], [], set()
    for text in keys:
        try:
            k = parse_ssh_key(text)
        except ValidationError as exc:
            refused.append((str(text)[:40], str(exc)))
            continue
        if k["type"] not in HOST_KEY_TYPES:
            refused.append((k["line"][:40], f"{k['type']} is not a host key type fabric signs"))
            continue
        if _family(k["type"]) in families:
            refused.append((k["line"][:40], f"a second {_family(k['type'])} key (the first is signed)"))
            continue
        families.add(_family(k["type"]))
        if k["fingerprint"] in by_key:
            keep.append(by_key[k["fingerprint"]])
        else:
            sign.append(k["line"])
    have = sorted(" ".join(str(c).split()[:2]) for c in certs)
    return {"keep": keep, "sign": sign, "refused": refused, "changed": bool(sign) or sorted(keep) != have}
