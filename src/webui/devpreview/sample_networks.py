"""The dev preview's sample address plan (manual 1.10.4, 1.10.4.40): two sites of one domain, shaped like read_plan's
answer, with this site's leases beside it (nothing here is real). Copied into each DevState and changed there by
fake_ipam."""

SAMPLE_NETWORK_VARS = {"site_name": "lan", "host_ip": "192.168.1.2", "domain": "home.arpa", "install_kea": True,
                       "dhcp": {"options": [{"name": "time-offset", "data": "-18000"}]}}
# the scans requested at parents (list_scan_requests' shape, 1.10.4.36): one answered, one pending
SAMPLE_SCAN_REQUESTS = [
    {"id": "scan-20261013093000-a1b2c3", "site": "parents", "subnet": "iot", "cidr": "10.2.20.0/24",
     "requested_by": "lan", "actor": "alice", "state": "done", "created": "2026-10-13T09:30:00Z", "late": False,
     "result": {"subnet": {"name": "iot", "cidr": "10.2.20.0/24"}, "at": "2026-10-13T09:30:20", "scanned": 254,
                "answering": 2, "unrecorded": 1, "truncated": 0,
                "rows": [{"ip": "10.2.20.77", "mac": "aa:bb:cc:00:00:77", "how": "ping+arp", "status": "unrecorded",
                          "kind": "", "name": "", "note": ""},
                         {"ip": "10.2.20.1", "mac": "", "how": "ping", "status": "recorded", "kind": "gateway",
                          "name": "", "note": ""}]}},
    {"id": "scan-20261013094000-d4e5f6", "site": "parents", "subnet": "iot", "cidr": "10.2.20.0/24",
     "requested_by": "lan", "actor": "alice", "state": "pending", "created": "2026-10-13T09:40:00Z", "late": False,
     "result": None}]
# what the plan poll last reported, beside the Sync now button (manual 1.10.4.28)
SAMPLE_SYNC = {"kea": True, "polled": True, "usn": 4711, "rendered": "2026-10-13 09:30:00", "dns_pending": True}
# a scan of iot (scan_subnet's shape): one find nobody recorded, one with no MAC, one recorded
SAMPLE_SCAN = {"subnet": {"name": "iot", "cidr": "10.1.20.0/24"}, "scanned": 254, "unrecorded": 2,
               "at": "2026-10-13T09:31:00",
               "answering": [{"ip": "10.1.20.10", "mac": "02:00:00:00:00:10", "how": "ping+arp", "status": "recorded",
                              "kind": "static", "name": "nas", "note": ""},
                             {"ip": "10.1.20.77", "mac": "aa:bb:cc:00:00:77", "how": "ping+arp",
                              "status": "unrecorded", "kind": "", "name": "", "note": ""},
                             {"ip": "10.1.20.88", "mac": "", "how": "ping", "status": "unrecorded", "kind": "",
                              "name": "", "note": "no MAC: a routed VLAN"}]}
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
    # the domain's and each site's option sets (read_plan's "option_sets", manual 1.10.4.32)
    "option_sets": {"domain": {"options": [{"name": "domain-name-servers", "data": "10.1.10.53"}], "option_defs": [],
                               "client_classes": []},
                    "lan": {"options": [], "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}],
                            "client_classes": [{"name": "uefi", "test": "option[93].hex == 0x0007",
                                                "options": [{"name": "ntp-servers", "data": "10.1.10.4"}]}]},
                    "parents": {"options": [], "option_defs": [], "client_classes": []}},
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
                                    "options": [{"code": 67, "data": "cam.bin"}]}]},
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
