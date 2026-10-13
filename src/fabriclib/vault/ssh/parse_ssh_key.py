import base64
import binascii
import hashlib
import struct

from fabriclib.common.errors import ValidationError
from fabriclib.vault.ssh.constants import KEY_TYPES, MIN_RSA_BITS

CURVE_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}


def _strings(blob):
    """Purpose: the length-prefixed strings an OpenSSH public key blob is made of (RFC 4253 §6.6).
    Inputs:  blob — bytes.
    Returns: list of bytes.
    Fails:   ValidationError when a length runs past the end.
    Feeds:   parse_ssh_key."""
    out, i = [], 0
    while i < len(blob):
        if i + 4 > len(blob):
            raise ValidationError("the public key is damaged")
        (n,) = struct.unpack(">I", blob[i:i + 4])
        if i + 4 + n > len(blob):
            raise ValidationError("the public key is damaged")
        out.append(blob[i + 4:i + 4 + n])
        i += 4 + n
    return out


def parse_ssh_key(text):
    """Purpose: read and judge one OpenSSH public key before it is signed (manual 1.6.11.9.3): Ed25519, ECDSA and
             RSA of at least MIN_RSA_BITS bits (and the security-key forms); never DSA, a certificate or a private key.
    Inputs:  text — str, one line "<type> <base64> [comment]" (as in id_ed25519.pub).
    Returns: {"type", "bits" (int; 256 for Ed25519), "fingerprint" ("SHA256:<base64>", as ssh-keygen -l shows it),
             "line" ("<type> <base64>", the comment dropped)}.
    Fails:   ValidationError: not one line of a public key; a private key; a type fabric does not sign; base64 that
             does not decode, or whose blob names another type; RSA below MIN_RSA_BITS.
    Feeds:   vault/ssh/sign_ssh_key; vault/ssh/ssh_overview (the CA key's fingerprint)."""
    text = str(text or "").strip()
    if "PRIVATE KEY" in text:
        raise ValidationError("that is a private key: paste the public key (the .pub file), and keep the private one "
                              "to yourself")
    lines = [line for line in text.splitlines() if line.strip()]
    parts = lines[0].split() if len(lines) == 1 else []
    if len(parts) < 2:
        raise ValidationError("paste one public key: one line such as \"ssh-ed25519 AAAA... you@laptop\"")
    kind, b64 = parts[0], parts[1]
    if kind not in KEY_TYPES:
        raise ValidationError(f"key type {kind[:40]!r} is not signed: use Ed25519 (ssh-keygen -t ed25519), ECDSA, or "
                              f"RSA of at least {MIN_RSA_BITS} bits")
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError("the public key's base64 does not decode")
    fields = _strings(blob)
    if not fields or fields[0].decode(errors="replace") != kind:
        raise ValidationError("the public key's contents do not match its type")
    if kind == "ssh-rsa":
        if len(fields) < 3:
            raise ValidationError("the public key is damaged")
        bits = int.from_bytes(fields[2], "big").bit_length()
        if bits < MIN_RSA_BITS:
            raise ValidationError(f"RSA keys must have at least {MIN_RSA_BITS} bits (this one has {bits}): make a "
                                  "new one with ssh-keygen -t ed25519")
    elif "ecdsa" in kind:
        bits = CURVE_BITS.get(fields[1].decode(errors="replace") if len(fields) > 1 else "", 0)
        if not bits:
            raise ValidationError("the public key's curve is not one of nistp256, nistp384, nistp521")
    else:
        bits = 256
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"type": kind, "bits": bits, "fingerprint": fingerprint, "line": f"{kind} {b64}"}
