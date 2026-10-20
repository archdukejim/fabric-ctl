"""Device RBAC vocabulary, shared by the directory operations and the web UI; and the names of the groups fabric
makes in the domain (manual 1.6.13.3), as the DC's own code names them (src/containers/samba/group_names.py)."""
import re

DIRECTORY_ADMINS = "directory-admins"   # the Directory Administrators: the console's admin group (2.1.6.81)
FABRIC_MANAGED = "fabric-managed"       # the machines fabric manages (1.6.11.6, 1.6.13.3)
DC_HOSTS = "dc-hosts"                   # the hosts that run a DC (2.1.6.70)
MACHINE_TYPES = ("server", "desktop", "network")     # a machine's type: its OU and group (1.6.13.3)


def site_group(site):
    """Purpose: a site's group, its people and machines (2.1.6.81).
    Inputs:  site — str.
    Returns: str "site-<site>".
    Fails:   never.
    Feeds:   the directory's callers that name a site's group (sort_machines, create_admin)."""
    return f"site-{site}"

DEVICE_TYPES = ["laptop", "desktop", "phone", "tablet", "printer", "camera", "iot", "network", "server", "other"]

# permission -> (what it grants, what enforces it)
PERMISSIONS = {
    "network:eap-tls": ("Join the network with its certificate (802.1X EAP-TLS)", "FreeRADIUS"),
    "network:mab": ("Join the network by MAC address (MAB — printers, IoT)", "FreeRADIUS"),
    "dns:dhcp-register": ("Register its DHCP hostname in the DHCP zone", "Kea DHCP-DDNS"),
    "pki:acme": ("Obtain and renew certificates by ACME", "Step-CA"),
    "pki:scep": ("Enrol certificates by SCEP (MDM, network gear)", "Step-CA"),
}

DEVICE_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
ROLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){31}$")

# Device roles a new install starts with (created once; then edited or deleted like any other).
# No VLANs: fabric cannot know the site's VLAN numbers (empty = the switch port's default).
DEFAULT_DEVICE_ROLES = [
    ("workstations", ["network:eap-tls", "pki:acme"], "Laptops and desktops: certificate (EAP-TLS), renew by ACME"),
    ("phones-tablets", ["network:eap-tls"], "Phones and tablets: certificate (EAP-TLS)"),
    ("servers", ["network:eap-tls", "pki:acme"], "Servers: certificate (EAP-TLS), renew by ACME"),
    ("printers", ["network:mab"], "Printers: by MAC (MAB) — give them a restricted VLAN"),
    ("iot", ["network:mab"], "Cameras, sensors, appliances: by MAC (MAB) — give them a restricted VLAN"),
    ("network-gear", ["pki:scep"], "Switches and access points: certificates by SCEP"),
]
