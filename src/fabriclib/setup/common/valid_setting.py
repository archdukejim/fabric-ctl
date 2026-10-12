import ipaddress
import re

REQUIRED = ["domain", "hostname", "host_ip", "lan_cidr", "lan_gateway"]
LABELS = {
    "domain": "DNS domain (e.g. home.arpa)",
    "hostname": "This host's name",
    "host_ip": "This host's LAN address",
    "lan_cidr": "LAN subnet (CIDR)",
    "lan_gateway": "LAN gateway (router)",
    "friendly_name": "Organisation's name (names the CA)",
    "webui_admin_user": "First admin's user name",
}
ADMIN_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
# names the first admin cannot take: the system's own, and AD's built-in accounts
RESERVED = {"admin", "root", "administrator", "guest", "krbtgt", "nobody", "daemon"}
FIRST_ADMIN = "fabric-admin"     # the recommended first admin: the one fabric- name a person may have (2.1.6.33)
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def valid_setting(key, value):
    """Purpose: check one answer or vars value for a required or asked setting, as strictly as what uses it later, so a
             bad answer is asked again at once instead of failing a later step (the owner's first install, 2.3.6.2.11).
    Inputs:  key — setting name (host_ip, lan_gateway, lan_cidr, webui_admin_user, domain, hostname, friendly_name, or
             other); value — str.
    Returns: True if valid: an IPv4 address; an IPv4 network; an admin username matching ADMIN_RE that no system or
             AD account uses (RESERVED, and not fabric-… other than FIRST_ADMIN, 2.1.6.33); a domain of two labels or
             more that is not `.local` (mDNS) or `localhost`; a host name of one DNS label, not `localhost` (the DC
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
        elif key == "webui_admin_user":
            return (bool(ADMIN_RE.match(value)) and value not in RESERVED
                    and (value == FIRST_ADMIN or not value.startswith("fabric-")))
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
