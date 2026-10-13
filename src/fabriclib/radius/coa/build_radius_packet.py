import hashlib
import hmac
import struct

from fabriclib.radius.coa.attributes import MESSAGE_AUTHENTICATOR


def build_radius_packet(code, ident, secret, attrs):
    """Purpose: a Disconnect-Request or CoA-Request as RFC 5176 signs it, with a Message-Authenticator.
    Inputs:  code — int (40 Disconnect-Request, 43 CoA-Request); ident — int 0..255; secret — str or bytes, the
             client's shared secret; attrs — list of (type int, value bytes), in order (no Message-Authenticator:
             it is added last).
    Returns: bytes, the packet. The Message-Authenticator is HMAC-MD5 over the packet with a zero Request
             Authenticator and itself zeroed; then the Request Authenticator is MD5(code, ident, length, 16 zero
             octets, attributes, secret) (RFC 5176 sections 2.3 and 3.5).
    Fails:   ValueError for a value that does not fit one attribute (253 bytes), an empty secret, or a packet over
             4096 bytes; struct.error for an ident or type out of range.
    Feeds:   send_coa; tests/freeradius/coa_packet_test.py.
    """
    key = secret.encode() if isinstance(secret, str) else bytes(secret)
    if not key:
        raise ValueError("a RADIUS packet needs the client's shared secret")
    body = b""
    for kind, value in attrs:
        if len(value) > 253:
            raise ValueError("a RADIUS attribute holds at most 253 bytes")
        body += struct.pack("!BB", kind, len(value) + 2) + value
    body += struct.pack("!BB", MESSAGE_AUTHENTICATOR, 18) + b"\0" * 16
    length = 20 + len(body)
    if length > 4096:
        raise ValueError("a RADIUS packet holds at most 4096 bytes")
    head = struct.pack("!BBH", code, ident, length)
    mac = hmac.new(key, head + b"\0" * 16 + body, hashlib.md5).digest()
    body = body[:-16] + mac
    authenticator = hashlib.md5(head + b"\0" * 16 + body + key).digest()
    return head + authenticator + body
