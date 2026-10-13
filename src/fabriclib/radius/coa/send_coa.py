import ipaddress
import secrets as _random
import socket

from fabriclib.radius.coa.build_radius_packet import build_radius_packet
from fabriclib.radius.coa.read_radius_reply import read_radius_reply


def send_coa(address, port, secret, code, attrs, timeout=3, tries=3):
    """Purpose: send one Disconnect-Request or CoA-Request to a switch over UDP and wait for its answer (RFC 5176).
    Inputs:  address — str, the NAS's IP address; port — int (Cisco: 3799 as fabric's configuration sets it);
             secret — the client's shared secret; code — 40 or 43; attrs — list of (type, bytes) (build_radius_packet);
             timeout — seconds per try (default 3); tries — how many times the same packet is sent (default 3).
    Returns: read_radius_reply's dict {"ack", "code", "error_cause", "error"}; when the switch only sent datagrams
             that are not a valid answer (another identifier, a bad signature: often a different secret on the
             switch), {"ack": False, "code": None, "error_cause": None, "error": "answered, but <why>"}; None when
             nothing came from the switch. Datagrams from any other address are ignored.
    Fails:   ValueError from build_radius_packet or for an address that is not an IP; OSError from the socket
             (no route, permission).
    Feeds:   coa_session.
    """
    ip = ipaddress.ip_address(str(address))
    packet = build_radius_packet(code, _random.randbelow(256), secret, attrs)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    invalid = ""
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _ in range(max(1, tries)):
            sock.sendto(packet, (str(ip), int(port)))
            try:
                while True:
                    data, sender = sock.recvfrom(4096)
                    if ipaddress.ip_address(sender[0]) != ip:
                        continue                 # only the switch itself answers
                    try:
                        return read_radius_reply(data, packet, secret)
                    except ValueError as exc:
                        invalid = str(exc)       # not an answer to this packet: keep listening
            except socket.timeout:
                continue
    if invalid:
        return {"ack": False, "code": None, "error_cause": None, "error": "answered, but " + invalid}
    return None
