import hashlib
import hmac
import struct

from fabriclib.radius.coa.attributes import ERROR_CAUSE, ERROR_CAUSES, MESSAGE_AUTHENTICATOR, REPLIES


def read_radius_reply(reply, request, secret):
    """Purpose: check a switch's answer to a Disconnect-Request or CoA-Request and read it (RFC 5176).
    Inputs:  reply — bytes received; request — bytes, the packet it answers (build_radius_packet's); secret — str or
             bytes, the client's shared secret.
    Returns: {"ack": bool, "code": int, "error_cause": int or None, "error": str ("" or the cause's name)}.
    Fails:   ValueError, with why, for an answer that is not to this request: too short or malformed, another
             identifier, a code that is not this request's ACK or NAK, a wrong Response Authenticator (MD5 of code,
             identifier, length, the request's authenticator, attributes and secret), or a wrong Message-Authenticator
             (when the answer carries one).
    Feeds:   send_coa; tests/freeradius/coa_packet_test.py.
    """
    key = secret.encode() if isinstance(secret, str) else bytes(secret)
    if len(reply) < 20:
        raise ValueError("the answer is too short to be RADIUS")
    code, ident, length = struct.unpack("!BBH", reply[:4])
    if length < 20 or length > len(reply):
        raise ValueError("the answer's length is wrong")
    reply = reply[:length]
    if ident != request[1]:
        raise ValueError("the answer is for another request (identifier)")
    if code not in REPLIES.get(request[0], ()):
        raise ValueError(f"the answer's code {code} does not answer this request")
    req_auth = request[4:20]
    expected = hashlib.md5(reply[:4] + req_auth + reply[20:] + key).digest()
    if not hmac.compare_digest(expected, reply[4:20]):
        raise ValueError("the answer is not signed with this client's secret (Response Authenticator)")
    attrs, pos, cause = reply[20:], 0, None
    while pos < len(attrs):
        if pos + 2 > len(attrs) or attrs[pos + 1] < 2 or pos + attrs[pos + 1] > len(attrs):
            raise ValueError("the answer's attributes are malformed")
        kind, size = attrs[pos], attrs[pos + 1]
        value = attrs[pos + 2:pos + size]
        if kind == ERROR_CAUSE and size == 6:
            cause = struct.unpack("!I", value)[0]
        if kind == MESSAGE_AUTHENTICATOR:
            if size != 18:
                raise ValueError("the answer's Message-Authenticator is malformed")
            zeroed = reply[:4] + req_auth + reply[20:20 + pos + 2] + b"\0" * 16 + reply[20 + pos + size:]
            if not hmac.compare_digest(hmac.new(key, zeroed, hashlib.md5).digest(), value):
                raise ValueError("the answer's Message-Authenticator is wrong")
        pos += size
    ack = code == REPLIES[request[0]][0]
    return {"ack": ack, "code": code, "error_cause": cause,
            "error": "" if cause is None else ERROR_CAUSES.get(cause, f"Error-Cause {cause}")}
