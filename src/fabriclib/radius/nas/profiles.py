"""What fabric knows about each vendor of RADIUS client (NAS): the one place these facts live (manual 1.11.1.2,
decision 2.1.11.4). Sources, and what could not be confirmed, are in the notes (2.3.11.5).

Each profile:
  label     — how the console names it.
  policy    — what FreeRADIUS's policy needs (rendered into fabric-radius.json per client):
              vlan: the reply attributes that put a client on a VLAN ("rfc3580": Tunnel-Type VLAN, Tunnel-Medium-Type
              IEEE-802, Tunnel-Private-Group-Id);
              mab: how a genuine MAB request looks — service_type (a Service-Type it must carry, or None),
              password_is_mac (a User-Password, when sent, must be the same MAC).
  radsec    — whether the client may use RadSec (RADIUS over TLS, TCP 2083).
  coa       — the CoA / Disconnect support fabric uses: None, or {port, actions: {action: how}}; how is
              ("disconnect",) for an RFC 5176 Disconnect-Request, or ("coa", <Cisco-AVPair value>) for a CoA-Request.
  no_coa    — why CoA is refused for this vendor, and what to do instead (None when coa is set).
  guide     — the setup page section on the FreeRADIUS tab (view=switches).
"""

VENDORS = ("unifi", "cisco", "generic")
DEFAULT_VENDOR = "generic"
TRANSPORTS = ("udp", "radsec")
DEFAULT_TRANSPORT = "udp"
RADSEC_PORT = 2083
RADSEC_SECRET = "radsec"            # RFC 6614 section 2.3: the shared secret inside TLS
RADSEC_CN_PREFIX = "radsec-"        # a RadSec client's certificate: CN radsec-<client name>
COA_ACTIONS = ("disconnect", "reauthenticate", "bounce")

PROFILES = {
    "unifi": {
        "label": "UniFi (UniFi Network: switches and access points)",
        "policy": {"vlan": "rfc3580", "mab": {"service_type": None, "password_is_mac": True}},
        "radsec": False,
        "coa": None,
        "no_coa": "UniFi does not document RADIUS CoA or Disconnect (RFC 5176), so fabric sends neither. Instead: "
                  "disable the device (or change its role) in fabric, then reconnect it in UniFi Network (Client "
                  "Devices -> the client -> Reconnect) or wait for its next authentication.",
        "guide": "unifi",
    },
    "cisco": {
        "label": "Cisco (Catalyst, IOS-XE)",
        "policy": {"vlan": "rfc3580", "mab": {"service_type": "Call-Check", "password_is_mac": False}},
        "radsec": True,
        "coa": {"port": 3799,
                "actions": {"disconnect": ("disconnect",),
                            "reauthenticate": ("coa", "subscriber:command=reauthenticate"),
                            "bounce": ("coa", "subscriber:command=bounce-host-port")}},
        "no_coa": None,
        "guide": "cisco",
    },
    "generic": {
        "label": "Other (generic RADIUS)",
        "policy": {"vlan": "rfc3580", "mab": {"service_type": None, "password_is_mac": False}},
        "radsec": False,
        "coa": None,
        "no_coa": "fabric does not know whether this switch accepts CoA or Disconnect, so it sends neither. Instead: "
                  "disable the device (or change its role) in fabric and reconnect it on the switch, or wait for its "
                  "next authentication. Set the client's vendor if it is UniFi or Cisco.",
        "guide": "generic",
    },
}
