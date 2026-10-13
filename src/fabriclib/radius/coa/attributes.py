"""RADIUS codes and attribute encoders for the Disconnect and CoA packets fabric sends (RFC 2865, RFC 5176)."""
import ipaddress
import struct

DISCONNECT_REQUEST, DISCONNECT_ACK, DISCONNECT_NAK = 40, 41, 42
COA_REQUEST, COA_ACK, COA_NAK = 43, 44, 45
REPLIES = {DISCONNECT_REQUEST: (DISCONNECT_ACK, DISCONNECT_NAK), COA_REQUEST: (COA_ACK, COA_NAK)}

USER_NAME, NAS_IP_ADDRESS, VENDOR_SPECIFIC, CALLING_STATION_ID = 1, 4, 26, 31
ACCT_SESSION_ID, EVENT_TIMESTAMP, MESSAGE_AUTHENTICATOR, ERROR_CAUSE = 44, 55, 80, 101
CISCO_VENDOR_ID, CISCO_AVPAIR = 9, 1

# RFC 5176 section 3.5
ERROR_CAUSES = {201: "Residual Session Context Removed", 202: "Invalid EAP Packet", 401: "Unsupported Attribute",
                402: "Missing Attribute", 403: "NAS Identification Mismatch", 404: "Invalid Request",
                405: "Unsupported Service", 406: "Unsupported Extension", 407: "Invalid Attribute Value",
                501: "Administratively Prohibited", 502: "Request Not Routable (Proxy)",
                503: "Session Context Not Found", 504: "Session Context Not Removable",
                505: "Other Proxy Processing Error", 506: "Resources Unavailable", 507: "Request Initiated",
                508: "Multiple Session Selection Unsupported"}


def text(value):
    """Purpose: a text or string attribute's value.
    Inputs:  value — str (UTF-8 encoded) or bytes.
    Returns: bytes, 1..253 long.
    Fails:   ValueError for an empty value or one longer than 253 bytes.
    Feeds:   coa_session (Acct-Session-Id, Calling-Station-Id, User-Name), cisco_avpair."""
    data = value.encode() if isinstance(value, str) else bytes(value)
    if not 1 <= len(data) <= 253:
        raise ValueError("a RADIUS attribute holds 1 to 253 bytes")
    return data


def ipv4(address):
    """Purpose: an address attribute's value (NAS-IP-Address).
    Inputs:  address — str IPv4 address.
    Returns: 4 bytes.
    Fails:   ValueError for anything that is not an IPv4 address.
    Feeds:   coa_session."""
    return ipaddress.IPv4Address(str(address)).packed


def integer(number):
    """Purpose: an integer or time attribute's value (Event-Timestamp).
    Inputs:  number — int, 0 .. 2**32-1.
    Returns: 4 bytes, network order.
    Fails:   struct.error out of range.
    Feeds:   coa_session."""
    return struct.pack("!I", int(number))


def cisco_avpair(pair):
    """Purpose: a Cisco-AVPair (vendor 9, type 1) as a Vendor-Specific attribute's value, e.g.
             "subscriber:command=reauthenticate".
    Inputs:  pair — str.
    Returns: bytes: vendor id, vendor type, vendor length, the text.
    Fails:   ValueError from text for an empty or too long pair.
    Feeds:   coa_session (Cisco's CoA commands)."""
    data = text(pair)
    if len(data) > 247:
        raise ValueError("a Cisco-AVPair holds at most 247 bytes")
    return struct.pack("!IBB", CISCO_VENDOR_ID, CISCO_AVPAIR, len(data) + 2) + data
