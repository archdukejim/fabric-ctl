"""The dev preview's sample address plan (manual 1.10.4): a top site with one house below it, shaped like read_plan's
answer, with this site's leases beside it (nothing here is real). Changed in memory by dev_post_networks."""

SAMPLE_NETWORK_VARS = {"site_name": "lan", "host_ip": "192.168.1.2", "domain": "home.arpa",
                       "dhcp": {"options": [{"name": "time-offset", "data": "-18000"}]}}
SAMPLE_NETWORK_SITES = [{"name": "lan", "own": True}, {"name": "parents", "own": False}]
# the scan page's list (scannable_subnets' shape): the sample's DHCP subnets of this site
SAMPLE_SCAN_SUBNETS = [{"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "hosts": 254},
                       {"name": "guest", "cidr": "10.1.30.0/24", "vlan": 30, "hosts": 254}]
SAMPLE_NETWORK_LEASES = [
    {"ip": "10.1.20.120", "mac": "02:11:22:33:44:55", "hostname": "laptop1", "state": "active",
     "expires": "2026-10-13T08:00"},
    {"ip": "10.1.20.150", "mac": "aa:bb:cc:dd:ee:01", "hostname": "cam1", "state": "active",
     "expires": "2026-10-13T09:00"}]
_SPLIT = [{"kind": "gateway", "first": "10.1.20.1", "last": "10.1.20.1", "notes": ""},
          {"kind": "static", "first": "10.1.20.2", "last": "10.1.20.99", "notes": ""},
          {"kind": "dhcp", "first": "10.1.20.100", "last": "10.1.20.249", "notes": ""},
          {"kind": "reserved", "first": "10.1.20.250", "last": "10.1.20.254", "notes": ""}]
SAMPLE_NETWORK_READ = {
    "sites": [{"name": "lan", "created": "20261001000000.0Z", "block": 1},
              {"name": "parents", "created": "20261005000000.0Z", "block": 2}],
    # the organisation's and the site's option sets (read_plan's "option_sets", manual 1.10.4.24.1)
    "option_sets": {"org": {"options": [{"name": "domain-name-servers", "data": "10.1.10.53"}], "option_defs": [],
                            "client_classes": []},
                    "lan": {"options": [], "option_defs": [],
                            "client_classes": [{"name": "uefi", "test": "option[93].hex == 0x0007",
                                                "options": [{"name": "ntp-servers", "data": "10.1.10.4"}]}]}},
    "org_editors": [],
    "plans": {
        "lan": {"vlans": [{"id": 10, "name": "mgmt", "purpose": "switches and APs", "access": "full", "notes": ""},
                          {"id": 20, "name": "iot", "purpose": "cameras", "access": "full", "notes": ""},
                          {"id": 30, "name": "guest", "purpose": "", "access": "guest", "notes": ""}],
                "subnets": [
                    {"name": "mgmt", "cidr": "10.1.10.0/24", "vlan": 10, "kind": "subnet", "gateway": "10.1.10.1",
                     "dhcp": False, "id": 1, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "gateway", "first": "10.1.10.1", "last": "10.1.10.1", "notes": ""},
                                {"kind": "static", "first": "10.1.10.2", "last": "10.1.10.254", "notes": ""}],
                     "addresses": [{"ip": "10.1.10.3", "kind": "infrastructure", "name": "switch1", "mac": "",
                                    "owner": "network", "notes": "rack", "dns": True, "options": []}]},
                    {"name": "iot", "cidr": "10.1.20.0/24", "vlan": 20, "kind": "dhcp", "gateway": "10.1.20.1",
                     "dhcp": True, "id": 2, "relay": "", "notes": "cameras and sensors", "allow_overlap": "",
                     "options": [{"name": "ntp-servers", "data": "10.1.10.3"}], "ranges": _SPLIT,
                     "addresses": [{"ip": "10.1.20.10", "kind": "static", "name": "nas", "mac": "", "owner": "office",
                                    "notes": "", "dns": True, "options": []},
                                   {"ip": "10.1.20.150", "kind": "reservation", "name": "cam1",
                                    "mac": "aa:bb:cc:dd:ee:01", "owner": "", "notes": "front door", "dns": False,
                                    "options": [{"code": 67, "data": "cam.bin"}], "role": "iot"}]},
                    {"name": "guest", "cidr": "10.1.30.0/24", "vlan": 30, "kind": "dhcp", "gateway": "10.1.30.1",
                     "dhcp": True, "id": 3, "relay": "", "notes": "", "allow_overlap": "", "options": [],
                     "ranges": [{"kind": "dhcp", "first": "10.1.30.100", "last": "10.1.30.200", "notes": ""}],
                     "addresses": []}],
                "networks": [{"name": "lan", "cidr": "192.168.1.0/24", "kind": "lan", "vlan": None, "notes": "",
                              "allow_overlap": ""}]},
        "parents": {"vlans": [{"id": 20, "name": "iot", "purpose": "", "access": "full", "notes": ""}],
                    "subnets": [{"name": "iot", "cidr": "10.2.20.0/24", "vlan": 20, "kind": "dhcp",
                                 "gateway": "10.2.20.1", "dhcp": True, "id": 1, "relay": "", "notes": "",
                                 "allow_overlap": "", "options": [], "ranges": [], "addresses": []}],
                    "networks": []}}}
