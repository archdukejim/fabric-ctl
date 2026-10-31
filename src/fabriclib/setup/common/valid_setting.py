import ipaddress
import re

from fabriclib.setup.common.first_admin_refused import KEYS as ADMIN_KEYS, first_admin_refused

REQUIRED = ["domain", "hostname", "host_ip", "lan_cidr", "lan_gateway"]
LABELS = {
    "domain": "DNS domain (e.g. home.arpa)",
    "hostname": "This host's name",
    "host_ip": "This host's LAN address",
    "lan_cidr": "LAN subnet (CIDR)",
    "lan_gateway": "LAN gateway (router)",
    "friendly_name": "Organisation's name (names the CA)",
    "webui_admin_user": "First Directory Administrator's user name (your own, not fabric-admin)",
    "webui_admin_first_name": "Their first name",
    "webui_admin_last_name": "Their last name",
    "webui_admin_email": "Their e-mail address (optional: Enter for none)",
}
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def valid_setting(key, value):
    """Purpose: check one answer or vars value for a required or asked setting, as strictly as what uses it later, so a
             bad answer is asked again at once instead of failing a later step (the owner's first install, 2.3.6.2.11).
    Inputs:  key — setting name (host_ip, lan_gateway, lan_cidr, webui_admin_user, webui_admin_first_name,
             webui_admin_last_name, webui_admin_email, domain, hostname, friendly_name, or other); value — str.
    Returns: True if valid: an IPv4 address; an IPv4 network; the first Directory Administrator's user name, first
             and last names and e-mail address (optional) as first_admin_refused takes them (2.1.6.69: never
             fabric-admin or another of
             fabric's names); a domain of two labels or more that is not `.local` (mDNS) or `localhost`; a host
             name of one DNS label, not `localhost` (the DC
             has a name of its own, dc_name, 2.1.6.45); an organisation name of 1-40 printable characters without
             quotes, backslashes or <> (the CA's certificate names, at most 64 characters, are built from it); any
             other key just needs a value.
    Fails:   never — ValueError from ipaddress is turned into False.
    Feeds:   setup/collect_vars, setup/common/ask_setting, setup/advanced (the menu's required items)."""
    try:
        if key in ("host_ip", "lan_gateway"):
            ipaddress.IPv4Address(value)
        elif key == "lan_cidr":
            ipaddress.IPv4Network(value, strict=False)
        elif key in ADMIN_KEYS:
            return first_admin_refused(key, value) is None
        elif key == "domain":
            low = value.lower()
            return (bool(HOST_RE.match(value)) and "." in value and not low.endswith(".local")
                    and low != "localhost" and not low.endswith(".localhost"))
        elif key == "hostname":
            return bool(HOST_RE.match(value)) and "." not in value and value.lower() != "localhost"
        elif key == "friendly_name":
            return 0 < len(value) <= 40 and value.isprintable() and not any(c in value for c in '"\\<>')
        return bool(value)
    except ValueError:
        return False
