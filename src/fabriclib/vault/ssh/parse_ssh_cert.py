import base64
import binascii
import hashlib
import struct

from fabriclib.common.errors import ValidationError

# certificate type -> (the plain key's type, how many length-prefixed fields its public part has) (PROTOCOL.certkeys)
CERT_TYPES = {"ssh-ed25519-cert-v01@openssh.com": ("ssh-ed25519", 1),
              "ecdsa-sha2-nistp256-cert-v01@openssh.com": ("ecdsa-sha2-nistp256", 2),
              "ecdsa-sha2-nistp384-cert-v01@openssh.com": ("ecdsa-sha2-nistp384", 2),
              "ecdsa-sha2-nistp521-cert-v01@openssh.com": ("ecdsa-sha2-nistp521", 2),
              "ssh-rsa-cert-v01@openssh.com": ("ssh-rsa", 2)}
KINDS = {1: "user", 2: "host"}


def _fingerprint(blob):
    """Purpose: an OpenSSH key fingerprint, as ssh-keygen -l shows it.
    Inputs:  blob — bytes, a public key blob.
    Returns: "SHA256:<base64 without padding>".
    Fails:   never.
    Feeds:   parse_ssh_cert."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _take(blob, at, n):
    """Purpose: n bytes of a certificate blob from position at.
    Inputs:  blob — bytes; at — int; n — int.
    Returns: (bytes, the position after them).
    Fails:   ValidationError when the blob runs short.
    Feeds:   _string, parse_ssh_cert."""
    if at + n > len(blob):
        raise ValidationError("the SSH certificate is damaged")
    return blob[at:at + n], at + n


def _string(blob, at):
    """Purpose: one length-prefixed string of a certificate blob (RFC 4251 §5).
    Inputs:  blob — bytes; at — int.
    Returns: (bytes, the position after it).
    Fails:   ValidationError when the blob runs short.
    Feeds:   parse_ssh_cert."""
    raw, at = _take(blob, at, 4)
    return _take(blob, at, struct.unpack(">I", raw)[0])


def _number(blob, at, size):
    """Purpose: one big-endian unsigned number of a certificate blob (uint32 or uint64).
    Inputs:  blob — bytes; at — int; size — 4 or 8.
    Returns: (int, the position after it).
    Fails:   ValidationError when the blob runs short.
    Feeds:   parse_ssh_cert."""
    raw, at = _take(blob, at, size)
    return int.from_bytes(raw, "big"), at


def parse_ssh_cert(text):
    """Purpose: read one OpenSSH certificate line (manual 1.6.11.9.8: the signing run judges the host certificates it
             finds in the directory before keeping one): its kind, the key it certifies, its principals, its validity
             and the CA that signed it. The signature itself is not checked here: sshd and ssh check it, and fabric
             only keeps certificates OpenBao gave it.
    Inputs:  text — str, "<type>-cert-v01@openssh.com <base64> [comment]".
    Returns: {"type" (the plain key's type), "kind" ("host" or "user"), "key_fingerprint" (of the certified key, as
             parse_ssh_key gives it), "principals" (list of str), "valid_after", "valid_before" (int, seconds since
             1970 UTC), "ca_fingerprint", "serial" (int), "key_id" (str), "line" ("<type> <base64>")}.
    Fails:   ValidationError: not one certificate line, a type fabric does not handle, base64 that does not decode, a
             blob that names another type or runs short, an unknown certificate kind.
    Feeds:   vault/ssh/plan_host_certs; vault/ssh/ssh_hosts_overview."""
    parts = str(text or "").strip().split()
    if len(parts) < 2 or parts[0] not in CERT_TYPES:
        raise ValidationError("not an SSH certificate of a type fabric handles")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError("the SSH certificate's base64 does not decode")
    kind_name, at = _string(blob, 0)
    if kind_name.decode(errors="replace") != parts[0]:
        raise ValidationError("the SSH certificate's contents do not match its type")
    _, at = _string(blob, at)                          # nonce
    base, fields = CERT_TYPES[parts[0]]
    start = at
    for _ in range(fields):
        _, at = _string(blob, at)
    name = base.encode()
    key_blob = struct.pack(">I", len(name)) + name + blob[start:at]
    serial, at = _number(blob, at, 8)
    kind, at = _number(blob, at, 4)
    key_id, at = _string(blob, at)
    if kind not in KINDS:
        raise ValidationError("the SSH certificate is neither a user nor a host certificate")
    packed, at = _string(blob, at)
    principals, p = [], 0
    while p < len(packed):
        one, p = _string(packed, p)
        principals.append(one.decode(errors="replace"))
    after, at = _number(blob, at, 8)
    before, at = _number(blob, at, 8)
    for _ in range(3):                                 # critical options, extensions, reserved
        _, at = _string(blob, at)
    ca, at = _string(blob, at)
    return {"type": base, "kind": KINDS[kind], "key_fingerprint": _fingerprint(key_blob), "principals": principals,
            "valid_after": after, "valid_before": before, "ca_fingerprint": _fingerprint(ca), "serial": serial,
            "key_id": key_id.decode(errors="replace"), "line": f"{parts[0]} {parts[1]}"}
