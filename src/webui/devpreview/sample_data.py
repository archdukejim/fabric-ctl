"""The dev preview's sample data: what a small home install looks like (nothing here is real)."""
import time

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV"]
# the site zone's names fabric adds on every render (fabriclib.dns.common.fabric_record): (type, name) -> (service,
# setting); the preview marks them "provided by fabric" and refuses their delete as fabric-agent does (2.1.2.22)
SAMPLE_FABRIC_NAMES = {("A", "fabric"): ("this host", "hostname"),
                       ("A", "@"): ("the domain itself, which serves the landing page", "host_ip"),
                       ("CNAME", "ca"): ("the CA (step-ca)", "cname_ca"), ("CNAME", "dns"): ("DNS (BIND)", "cname_dns"),
                       ("CNAME", "sso"): ("sign-in (Keycloak)", "cname_sso")}
SAMPLE_RADIUS = {"enabled": True, "server_name": "radius.home.arpa", "host_ip": "192.168.1.2",
                 "clients": [{"name": "switch1", "address": "192.168.1.3", "message_authenticator": True},
                             {"name": "ap-hall", "address": "192.168.1.4", "message_authenticator": False}],
                 "people": [{"group": "staff", "vlan": 20, "priority": 50},
                            {"group": "guests", "vlan": 50, "priority": 60}],
                 "log": [{"time": "2026-09-29T20:14:02", "decision": "ACCEPT", "method": "eap-tls",
                          "device": "jims-laptop", "vlan": "20", "mac": "02:11:22:33:44:55", "nas": "switch1",
                          "reason": ""},
                         {"time": "2026-09-29T20:13:10", "decision": "ACCEPT", "method": "eap-ttls", "device": "alice",
                          "person": True, "vlan": "20", "mac": "02:11:22:33:44:66", "nas": "ap-hall", "reason": ""},
                         {"time": "2026-09-29T20:12:40", "decision": "REJECT", "method": "mab", "device": "cam-front",
                          "vlan": "-", "mac": "02:aa:bb:cc:dd:01", "nas": "switch1", "reason": "device disabled"}],
                 "log_error": ""}
SAMPLE_DHCP = {"enabled": True, "interfaces": ["eth0"], "lease_time": 86400, "ddns_zone": "dhcp.home.arpa",
               "has_settings": True,
               "host_interfaces": [{"name": "eth0", "address": "192.168.1.2", "network": "192.168.1.0/24"},
                                   {"name": "eth1", "address": "10.20.0.10", "network": "10.20.0.0/24"}],
               "subnets": [{"subnet": "192.168.1.0/24", "id": 1, "name": "main", "vlan": 1,
                            "notes": "the house LAN", "pools": ["192.168.1.100 - 192.168.1.199"],
                            "routers": "192.168.1.1", "options": [{"name": "ntp-servers", "data": "192.168.1.2"}],
                            "reservations": [{"mac": "aa:bb:cc:00:11:22", "ip": "192.168.1.20",
                                              "hostname": "printer"}]}],
               "leases": [{"ip": "192.168.1.101", "mac": "02:11:22:33:44:55", "hostname": "laptop1.dhcp.home.arpa",
                           "expires": "2026-09-30T08:00", "state": "active", "subnet_id": 1}],
               "leases_error": "", "options": [{"name": "time-offset", "data": "-18000"}], "overrides": [],
               "option_defs": [], "client_classes": [{"name": "pxe-uefi", "test": "option[93].hex == 0x0007",
                                                      "next_server": "192.168.1.30", "boot_file_name": "ipxe.efi",
                                                      "options": [{"name": "tftp-server-name",
                                                                   "data": "192.168.1.30"}]}]}
SAMPLE = {
    "services": [("nginx", "active", "healthy"), ("bind9", "active", "healthy"), ("stepca", "active", "healthy"),
                 ("samba", "active", "healthy"), ("postgres", "active", "healthy"), ("keycloak", "active", "healthy"),
                 ("openbao", "active", "healthy"), ("fabric-web", "active", "healthy"), ("fabric-agent", "active", "")],
    "host_changes": [
        {"group": g, "title": t, "state": st, "when": "2026-10-03T09:12:40+00:00" if st != "not asked" else "",
         "by": "admin" if st != "not asked" else "", "relaxation": r}
        for g, t, st, r in (
            ("packages", "Packages", "approved", ""), ("runtime", "Docker daemon settings", "approved", ""),
            ("services", "fabric's own services", "approved", ""), ("accounts", "Service accounts", "approved", ""),
            ("resolver", "Host DNS resolver", "not asked", ""), ("firewall", "Host firewall", "approved", ""),
            ("trust", "Host trust store", "declined", "this host does not trust fabric's CA: tools on the host (curl, "
                                                     "apt, browsers) reject fabric's certificates unless given the CA"),
            ("time", "Time service (chrony)", "approved", ""))],
    "zones": {
        "dynamic_zone_var": {"name": "home.arpa", "records": [
            ("A", "fabric", "192.168.1.53"), ("A", "@", "192.168.1.53"), ("A", "nas", "192.168.1.10"),
            ("CNAME", "ca", "fabric"), ("CNAME", "info", "fabric"), ("CNAME", "dns", "fabric"),
            ("A", "printer", "192.168.1.40"), ("AAAA", "nas", "fd00:1:2:3::10"), ("A", "vpn", "203.0.113.7"),
            ("CNAME", "ca", "fabric"), ("CNAME", "info", "fabric"), ("CNAME", "dns", "fabric"),
            ("CNAME", "sso", "fabric"), ("MX", "@", "10 mail"), ("TXT", "@", '"v=spf1 -all"')],
            "links": {"A|nas": {"label": "NAS", "port": 5001, "path": None}}},
        "iot.home.arpa": {"name": "iot.home.arpa", "records": [
            ("A", "cam-front", "192.168.20.11"), ("A", "cam-back", "192.168.20.12"), ("A", "thermostat",
                                                                                      "192.168.20.30")]},
    },
    "audit": ["[dev] User: dev (web) | Action: LOGIN | dev preview — no certificate, no Keycloak\n"],
    "tsig": [{"name": "npm-certbot", "algorithm": "hmac-sha256", "types": "TXT",
              "scope": "_acme-challenge.npm.home.arpa, _acme-challenge.nas.home.arpa", "acls": ["certbot-devices"]},
             {"name": "home.arpa-acme", "algorithm": "hmac-sha256", "types": "TXT",
              "scope": "_acme-challenge (zone home.arpa)", "acls": []}],
    "directory": {
        "roles": [{"name": "trusted", "description": "Managed laptops and phones", "priority": 10, "vlan": 10,
                   "permissions": ["dns:dhcp-register", "network:eap-tls", "pki:acme"], "members": ["jims-laptop",
                                                                                                    "jims-phone"]},
                  {"name": "iot", "description": "Cameras, plugs, thermostats", "priority": 50, "vlan": 30,
                   "permissions": ["dns:dhcp-register", "network:mab"], "members": ["cam-front", "thermostat"]},
                  {"name": "printers", "description": "", "priority": 60, "vlan": None,
                   "permissions": ["network:mab", "pki:scep"], "members": ["printer"]},
                  {"name": "quarantine", "description": "No access; parked devices", "priority": 1, "vlan": 99,
                   "permissions": [], "members": []}],
        "devices": [{"name": "jims-laptop", "type": "laptop", "enabled": True, "macs": ["3c:22:fb:10:20:30"],
                     "owner": "uid=jim,ou=users", "description": "ThinkPad", "certs": [":".join(["AB"] * 32)]},
                    {"name": "jims-phone", "type": "phone", "enabled": True, "macs": ["f2:11:22:33:44:55"],
                     "owner": "uid=jim,ou=users", "description": "", "certs": []},
                    {"name": "cam-front", "type": "camera", "enabled": True, "macs": ["b0:a7:32:00:00:11"],
                     "owner": "", "description": "Front door", "certs": []},
                    {"name": "thermostat", "type": "iot", "enabled": False, "macs": ["18:b4:30:aa:bb:cc"],
                     "owner": "", "description": "Disabled: firmware out of date", "certs": []},
                    {"name": "printer", "type": "printer", "enabled": True, "macs": ["00:1b:a9:12:34:56"],
                     "owner": "", "description": "Office laser", "certs": []}]},
    "people": {"users": [{"uid": "jim", "name": "Jim", "mail": "jim@home.arpa", "locked": False, "groups": ["admins",
                                                                                                            "users"]},
                         {"uid": "sam", "name": "Sam", "mail": "sam@home.arpa", "locked": False, "groups": ["users"]}],
               "groups": [{"name": "admins", "members": 1}, {"name": "users", "members": 2}],
               "keycloak_url": "https://sso.home.arpa/admin/home.arpa/console/"},
    "issued": [{"when": "2026-09-20T10:12:00", "actor": "dev", "kind": "csr", "subject": "CN=switch-core.home.arpa",
                "sans": ["switch-core.home.arpa", "192.168.1.2"], "not_after": "Sep 20 10:12:00 2027 GMT",
                "status": "valid"},
               {"when": "2025-10-01T08:00:00", "actor": "dev", "kind": "keypair", "subject": "CN=printer.home.arpa",
                "sans": ["printer.home.arpa"], "not_after": "Oct 15 08:00:00 2026 GMT", "status": "expires soon"}],
}
_FP = ":".join(["AB", "12", "CD", "34"] * 8)
SAMPLE_VAULT = {"url": "https://vault.home.arpa/", "reachable": True, "initialized": True, "sealed": False,
                "version": "2.7.0", "seal_type": "static", "storage": "raft", "recovery_seal": True,
                "key": {"path": "/etc/fabric/openbao/unseal.key", "present": True, "ok": True,
                        "detail": "32 bytes, 0400, openbao only"},
                "mounts": [{"path": "apps/", "type": "kv", "version": "2",
                            "description": "secrets for your applications"},
                           {"path": "cubbyhole/", "type": "cubbyhole", "version": None,
                            "description": "per-token private secret storage"},
                           {"path": "fabric/", "type": "kv", "version": "2", "description": "fabric's own secrets"},
                           {"path": "identity/", "type": "identity", "version": None, "description": "identity store"},
                           {"path": "sys/", "type": "system", "version": None, "description": "system endpoints"}],
                "auth": ["approle/", "oidc/", "token/"], "secrets": {"version": 7, "updated": "2026-09-29T09:12:44"}}
SAMPLE_SLOTS = [
    {"id": "local", "type": "local", "label": "Key file on this host", "device": "/etc/fabric/openbao/unseal.key",
     "present": True, "key_id": "fabric-1", "added": "2026-09-28",
     "detail": "always present: while this slot exists, removing a device cannot seal the vault"},
    {"id": "s-yk1", "type": "security-key", "label": "Pi key", "device": "YubiKey 5 Nano · serial 23456781 · key 03",
     "present": True, "key_id": "fabric-1", "added": "2026-09-29",
     "detail": "the key cannot be copied; its PIN is kept root-only on this host"}]
SAMPLE_DEVICES = {"tokens": [{"vendor": "Yubico", "product": "YubiKey OTP+FIDO+CCID", "serial": "23456781",
                              "usb_id": "1050:0407", "port": "1-1.2"},
                             {"vendor": "Yubico", "product": "YubiKey OTP+FIDO+CCID", "serial": "23456799",
                              "usb_id": "1050:0407", "port": "1-1.3"}],
                  "disks": [{"path": "/dev/sda", "model": "SanDisk Ultra Fit", "serial": "4C530001230912104582",
                             "size_gb": 32.0, "uuids": ["9A1C-33F0"], "labels": ["USB"]}],
                  "pkcs11": [{"module": "/usr/lib/aarch64-linux-gnu/libykcs11.so.2", "library": "libykcs11.so.2",
                              "serial": "23456781", "label": "YubiKey PIV #23456781",
                              "manufacturer": "Yubico (www.yubico.com)",
                              "model": "YubiKey YK5", "pin_state": "ok"},
                             {"module": "/usr/lib/aarch64-linux-gnu/libykcs11.so.2", "library": "libykcs11.so.2",
                              "serial": "23456799", "label": "YubiKey PIV #23456799",
                              "manufacturer": "Yubico (www.yubico.com)",
                              "model": "YubiKey YK5", "pin_state": "ok"}]}
SAMPLE_CA = {"domain": "home.arpa", "certs_url": "http://ca.home.arpa/certs/", "max_days": 1825,
             "root": {"subject": "CN=Fabric Root CA,O=Fabric", "not_after": "Sep  1 00:00:00 2046 GMT",
                      "key": "EC prime256v1", "sha256": _FP},
             "intermediate": {"subject": "CN=Fabric Intermediate CA,O=Fabric", "not_after": "Sep  1 00:00:00 2036 GMT",
                              "key": "EC prime256v1", "sha256": _FP}}
SAMPLE_PEM = "-----BEGIN CERTIFICATE-----\nDEV PREVIEW — sample, not a real certificate\n-----END CERTIFICATE-----\n"
# decodes (the Windows scripts hash it) but is no certificate: the preview's scripts are samples only
SAMPLE_ROOT_PEM = ("-----BEGIN CERTIFICATE-----\nREVWIFBSRVZJRVcgc2FtcGxlIHJvb3QgQ0EgLSBub3QgYSByZWFsIGNlcnRpZmljYXRl\n"
                   "-----END CERTIFICATE-----\n")
SAMPLE_KEY = "-----BEGIN PRIVATE KEY-----\nDEV PREVIEW — sample, not a real key\n-----END PRIVATE KEY-----\n"
SAMPLE_INFO = {"subject": "CN=device.home.arpa,OU=IT,O=Fabric", "issuer": "CN=Fabric Intermediate CA,O=Fabric",
               "sans": ["device.home.arpa", "192.168.1.50"], "key": "RSA 2048", "serial": "0x1A2B3C4D5E",
               "not_before": "Sep 28 00:00:00 2026 GMT", "not_after": "Sep 28 00:00:00 2027 GMT", "sha256": _FP,
               "usage": "TLS Web Server Authentication, TLS Web Client Authentication", "is_ca": False}
SAMPLE_DOMAIN = {"status": {"domain": "ad.home.arpa", "realm": "AD.HOME.ARPA", "netbios": "AD",
                            "dc": "pi-core.ad.home.arpa", "running": True,
                            "roles": [f"{r}Role owner: CN=NTDS Settings,CN=DC-PI-CORE,CN=Servers,CN=lan,CN=Sites,"
                                      "CN=Configuration,DC=ad,DC=home,DC=arpa"
                                      for r in ("SchemaMaster", "InfrastructureMaster", "RidAllocationMaster",
                                                "PdcEmulationMaster", "DomainNamingMaster", "DomainDnsZonesMaster",
                                                "ForestDnsZonesMaster")],
                            "role_summary": {"text": "This controller holds all five roles (and the 2 DNS zone "
                                                     "masters).", "held": [], "elsewhere": []}, "policy": []},
                 "policy": {"minimum_length": 14, "complexity": True, "history": 24, "minimum_age_days": 0,
                            "maximum_age_days": 0, "lockout_threshold": 5, "lockout_minutes": 15,
                            "lockout_window_minutes": 15},
                 "site": "lan", "machines_error": "",
                 "machines": [{"name": "host-1", "dns": "host-1.ad.home.arpa", "os": "Windows 11 Pro", "enabled": True,
                               "last_logon": "2026-10-05T08:12:00+00:00", "created": "2026-10-04", "dn": ""},
                              {"name": "ws2404", "dns": "ws2404.ad.home.arpa", "os": "", "enabled": False,
                               "last_logon": "", "created": "2026-10-05", "dn": ""}]}
SAMPLE_LOGON = {"site": "lan", "legacy": False, "error": "",
                "always": ["fabric-break-glass", "BUILTIN\\Administrators"],
                "policies": [{"ou": "machines", "console": ["lan-machine-admins"], "remote": ["lan-machine-admins"]},
                             {"ou": "machines/linux", "console": ["lan-machine-admins", "lan-devs"],
                              "remote": ["lan-devs"]}]}
SAMPLE_ACCESS = {"error": "",
                 "groups": [{"name": "lan-hosts-web", "short": "web", "machines": ["host-1"], "other_members": [],
                             "rules": ["web-restart"], "hosts": ["host-1", "host-1.ad.home.arpa"], "fabric": True}],
                 "sudo": [{"name": "lan-fabric-admins", "kind": "default", "users": ["%lan-fabric-admins"],
                           "commands": ["ALL"], "run_as": ["ALL"], "hosts": ["ALL"], "host_group": ""},
                          {"name": "web-restart", "kind": "fabric", "users": ["alice", "%lan-web-ops"],
                           "commands": ["/usr/bin/systemctl restart nginx"], "run_as": ["root"],
                           "hosts": ["host-1", "host-1.ad.home.arpa"], "host_group": "lan-hosts-web"},
                          {"name": "backup", "kind": "other", "users": ["%backup-ops"], "commands": ["/usr/bin/rsync"],
                           "run_as": ["root"], "hosts": ["ALL"], "host_group": ""}]}
SAMPLE_FEDERATION = {
    "site": "lan", "upstream": None,
    "sites": [{"name": "lab", "domain": "lab.home.arpa", "address": "192.168.20.2", "parent": "lan", "dc": "writable",
               "id_range": "105001-205000", "joined": "2026-10-05T09:00:00+02:00", "via": ""},
              {"name": "edge", "domain": "edge.home.arpa", "address": "192.168.30.2", "parent": "lan", "dc": "rodc",
               "id_range": "205001-305000", "joined": "2026-10-05T09:30:00+02:00", "via": ""}],
    "replication": {"error": "", "neighbours": [
        {"partition": "DC=ad,DC=home,DC=arpa", "from": "CN=NTDS Settings,CN=DC-LAB,CN=Servers,CN=lab,CN=Sites",
         "last_success": "2026-10-05 10:15:02", "failures": 0, "message": ""},
        {"partition": "DC=ad,DC=home,DC=arpa", "from": "CN=NTDS Settings,CN=DC-EDGE,CN=Servers,CN=edge,CN=Sites",
         "last_success": "2026-10-05 09:58:40", "failures": 3, "message": "WERR_BADFILE"}]},
    "conflicts": ["CN=printer\\0ACNF:5f0c,OU=devices,OU=lab,OU=sites,DC=ad,DC=home,DC=arpa"],
    "limits": [["fabric-agent-<site>, <site>-admins", "its own OU=<site>", "read only"]],
    "plan": [{"site": "lab", "name": "lan", "cidr": "192.168.20.0/24", "vlan": None, "notes": ""},
             {"site": "lan", "name": "lan", "cidr": "192.168.1.0/24", "vlan": None, "notes": ""}],
    "overlaps": [], "plan_error": ""}
SAMPLE_GPO = {"site": "lan", "templates": ["fabric-starter", "samba"], "match": "",
              "settings": {"machine": [["Software\\Policies\\Example\\Starter", "ExampleText", 1, "hello"]],
                           "user": []},
              "controls": {"machine": [["Software\\Policies\\Example\\Starter", "ExampleLocked", 4, 1]], "user": []},
              "policies": [{"template": "fabric-starter", "name": "ExampleSetting", "display": "Example setting",
                            "class": "Machine", "elements": ["text:ExampleText"]}], "more": False}
SAMPLE_SECURITY = [
    {"layer": "admin-2fa",
     "what": "a second factor for the admin tools (the web console, OpenBao's UI)",
     "value": "totp", "effective": "totp", "choices": ["passkey"], "lowered": None},
    {"layer": "everyone-2fa", "what": "a second factor for every sign-in (every app signing in through Keycloak)",
     "value": "none", "effective": "none", "choices": ["any", "totp", "passkey"],
     "lowered": {"from": "any", "to": "none", "by": "root (sudo by dev)", "at": "2026-10-07 12:00 UTC"}},
    {"layer": "client-cert", "what": "a client certificate from fabric's CA for the web console", "value": "off",
     "effective": "off", "choices": ["on"], "lowered": None},
    {"layer": "kerberos", "what": "signing in with the domain logon (Kerberos)", "value": "on", "effective": None,
     "choices": [], "lowered": None},
]
_REG = "ghcr.io/archdukejim/open-fabric"
SAMPLE_IMAGES = [
    {"service": "bind9", "var": "image_fabric_bind9", "running": f"{_REG}/bind9:0.6.3-rc.1@sha256:1111",
     "applied": f"{_REG}/bind9:0.6.3-rc.1@sha256:1111", "validated": f"{_REG}/bind9:0.6.3-rc.1@sha256:1111",
     "state": "current"},
    {"service": "postgres", "var": "image_postgres", "running": "postgres:18.4@sha256:a02d",
     "applied": "postgres:18.4@sha256:a02d", "validated": "postgres:18.6@sha256:5a5a", "state": "update available"},
    {"service": "nginx", "var": "image_nginx", "running": "nginx:1.30.5@sha256:b972",
     "applied": "nginx:1.30.5@sha256:b972", "validated": "nginx:1.30.5@sha256:b972", "state": "current"},
]
SAMPLE_DOCTOR = {"checks": [{"name": "DNS ns.home.arpa", "ok": True, "detail": ""},
                            {"name": "DNS-over-HTTPS https://ns.home.arpa/dns-query answers", "ok": True, "detail": ""},
                            {"name": "certificates: renewal working, none about to expire (2.1.5.4)", "ok": False,
                             "detail": "DEV PREVIEW: a sample failure"},
                            {"name": "service nginx", "ok": True, "detail": "active"}], "failed": 1}
SAMPLE_ACME = {"domain": "home.arpa", "machines": [{"name": "nas", "fqdn": "nas.home.arpa", "key": "acme-nas",
                                                    "records": ["nas"]}],
               "info": ["ACME directory: https://ca.home.arpa/acme/acme/directory",
                        "trust fabric's root CA first: http://ca.home.arpa/certs/ (check its fingerprint there)",
                        "names: <name>.home.arpa only; certificates live 47 days: let the client renew at 30 days old",
                        "http-01: the machine answers on port 80 for its name (nothing to enroll)",
                        "dns-01: enroll it below; its client sends RFC2136 updates with its key"]}
_REG_LIST = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_{}.txt"
_ZONE = "8f1c2d3e4a5b.list.rpz"
_NOW = int(time.time())          # the sample's lists were fetched a few hours ago
def _list(name, n, group, description, homepage, enabled=None, rules=None, memory=None, ago=3):
    """Purpose: one row of the sample's lists table, as filter_overview gives it (manual 1.12.3.5).
    Inputs:  name, n (its registry number), group, description, homepage; enabled — None: not on the site; rules,
             memory — its copy's state; ago — hours since its copy.
    Returns: dict.
    Fails:   never.
    Feeds:   SAMPLE_DNS_FILTER."""
    return {"id": f"{n:012x}", "name": name, "url": _REG_LIST.format(n), "description": description,
            "homepage": homepage, "category": group, "on_site": enabled is not None, "enabled": bool(enabled),
            "last_fetch": _NOW - ago * 3600, "last_success": _NOW - ago * 3600, "rules": rules, "memory_mb": memory,
            "error": None}


SAMPLE_DNS_FILTER = {
    "on": True, "catalogue_fetched": _NOW - 3 * 3600,
    "categories": ["General", "Security", "Regional", "Added by URL"],
    "lists": [_list("AdGuard DNS filter", 1, "General", "Blocks ads and trackers; few false positives.",
                    "https://github.com/AdguardTeam/AdGuardSDNSFilter", True, 178979, 24.5),
              _list("OISD Blocklist Small", 5, "General", "Blocks ads, mobile app ads, phishing and malware.",
                    "https://oisd.nl/", None, 56012, 7.7),
              _list("HaGeZi's Pro Blocklist", 48, "General", "Ads, affiliate, tracking, metrics, telemetry.",
                    "https://github.com/hagezi/dns-blocklists", False, 189433, 25.9),
              _list("Phishing Army", 18, "Security", "Phishing domains.", "https://phishing.army/", True, 151020,
                    20.6),
              _list("POL: Polish filters for Pi-hole", 14, "Regional", "Polish ad and tracker domains.", "", None,
                    23001, 3.1),
              {**_list("My list", 9999, "Added by URL", "", "", True, 12, 0.0),
               "url": "https://lists.example/mine.txt"}],
    "memory": {"estimate_mb": 45.1, "peak_mb": 112.8, "limit_mb": 1024.0, "fits": True, "unknown": []},
    "allow": ["doubleclick.net"], "block": ["ads.example.org"],
    "upstreams": [{"address": "1.1.1.1", "name": "cloudflare-dns.com"},
                  {"address": "1.0.0.1", "name": "cloudflare-dns.com"}],
    "safe_search": {"on": False, "youtube": "strict"},
    "groups": [{"name": "kids", "clients": ["192.168.1.64/27"], "safe_search": True, "youtube": "strict",
                "allow": ["khanacademy.org"], "block": ["roblox.com"]},
               {"name": "teen-laptop", "clients": ["192.168.1.70"], "safe_search": True, "youtube": "moderate",
                "allow": [], "block": []}],
    # the same engines and counts as fabriclib's table (dns_filter/common/safe_search), which the agent sends
    "safe_search_sites": {"engines": [{"engine": e, "names": n, "answer": a} for e, n, a in (
        ("Google", 187, "forcesafesearch.google.com"),
        ("YouTube", 5, "restrict.youtube.com or restrictmoderate.youtube.com"), ("Bing", 2, "strict.bing.com"),
        ("DuckDuckGo", 3, "safe.duckduckgo.com"), ("Yandex", 52, "213.180.193.56"),
        ("Pixabay", 1, "safesearch.pixabay.com"), ("Ecosia", 1, "strict-safe-search.ecosia.org"))],
        "not_covered": ["Brave Search", "Startpage"],
        "youtube": {"strict": "restrict.youtube.com", "moderate": "restrictmoderate.youtube.com"}},
    "stats": {"hours": [{"hour": f"2026-10-09T{h:02d}:00Z", "queries": q, "blocked": b}
                        for h, q, b in ((0, 412, 61), (1, 288, 40), (2, 190, 22), (3, 175, 19), (4, 230, 31),
                                        (5, 640, 98), (6, 1210, 170), (7, 1620, 233), (8, 1488, 206), (9, 1302, 188))],
              "week": {"queries": 48210, "blocked": 6940},
              "zones": [{"zone": _ZONE, "list": "AdGuard DNS filter", "queries": 6912, "blocked": 6912},
                        {"zone": "owner.rpz", "list": None, "queries": 140, "blocked": 28},
                        {"zone": "fabric.rpz", "list": None, "queries": 3920, "blocked": 0}],
              "top_blocked": [{"name": "browser.events.data.msn.com", "zone": _ZONE, "list": "AdGuard DNS filter",
                               "count": 1204},
                              {"name": "app-measurement.com", "zone": _ZONE, "list": "AdGuard DNS filter",
                               "count": 640},
                              {"name": "ads.example.org", "zone": "owner.rpz", "list": None, "count": 28}]}}
SAMPLE_QUERY_LOG = {"entries": [
    {"at": "2026-10-09T09:58:12Z", "client": "192.168.1.20", "view": "everyone", "name": "browser.events.data.msn.com",
     "qtype": "A", "action": "NXDOMAIN", "zone": _ZONE, "list": "AdGuard DNS filter", "blocked": True},
    {"at": "2026-10-09T09:58:11Z", "client": "192.168.1.66", "view": "kids", "name": "www.roblox.com",
     "qtype": "A", "action": "NXDOMAIN", "zone": "group-kids.rpz", "list": None, "blocked": True},
    {"at": "2026-10-09T09:58:10Z", "client": "192.168.1.20", "view": "everyone", "name": "www.wikipedia.org",
     "qtype": "AAAA", "action": None, "zone": None, "list": None, "blocked": False},
    {"at": "2026-10-09T09:57:55Z", "client": "192.168.1.31", "view": "everyone", "name": "nas.home.arpa",
     "qtype": "A", "action": "PASSTHRU", "zone": "fabric.rpz", "list": None, "blocked": False},
    {"at": "2026-10-09T09:57:41Z", "client": "192.168.1.31", "view": "everyone", "name": "ad.doubleclick.net",
     "qtype": "A", "action": "PASSTHRU", "zone": "owner.rpz", "list": None, "blocked": False},
    {"at": "2026-10-09T09:57:02Z", "client": "192.168.1.44", "view": "everyone", "name": "ads.example.org",
     "qtype": "A", "action": "NXDOMAIN", "zone": "owner.rpz", "list": None, "blocked": True}]}
# the DHCP options page (manual 1.10.4.24.6): what options_overview answers for a small two-house organisation
SAMPLE_OPTIONS = {
    "site": "home", "here": "home", "root": True, "org_editable": True, "org_editors": ["parents"], "settings": None,
    "org": {"options": [{"name": "v4-captive-portal", "data": "https://portal.home.arpa/"}], "option_defs": [],
            "client_classes": []},
    "site_options": {"options": [{"name": "ntp-servers", "data": "10.1.10.1"}],
                     "option_defs": [{"name": "ztp-url", "code": 239, "type": "string"}],
                     "client_classes": [{"name": "switches", "test": "substring(option[60].hex,0,5) == 'Cisco'",
                                         "options": [{"name": "ztp-url", "data": "http://ztp.home.arpa/cfg"}]}]},
    "subnets": [{"name": "lab", "cidr": "10.1.40.0/24", "vlan": 40, "id": 5, "dhcp": True,
                 "options": [{"name": "domain-name-servers", "data": "10.1.40.53"}],
                 "netboot": {"server": "10.1.10.5", "bios": "undionly.kpxe", "uefi": "ipxe.efi",
                             "ipxe": "http://boot.home.arpa/boot.ipxe"},
                 "reservations": [{"ip": "10.1.40.20", "name": "pxe-test", "mac": "aa:bb:cc:00:40:20",
                                   "options": [{"name": "boot-file-name", "data": "custom.efi"}], "netboot": None}]}],
    "catalogue": [{"code": 6, "name": "domain-name-servers"}, {"code": 42, "name": "ntp-servers"},
                  {"code": 66, "name": "tftp-server-name"}, {"code": 67, "name": "boot-file-name"},
                  {"code": 114, "name": "v4-captive-portal"}, {"code": 119, "name": "domain-search"}],
    "effective": None,
}
SAMPLE_EFFECTIVE = {
    "target": "subnet lab",
    "rows": [{"code": 3, "name": "routers", "data": "10.1.40.1", "source": "fabric (the subnet's gateway)",
              "provided": False, "fabric_overridden": False, "overrides": []},
             {"code": 6, "name": "domain-name-servers", "data": "10.1.40.53", "source": "subnet lab", "provided": True,
              "fabric_overridden": True, "overrides": ["fabric"]},
             {"code": 42, "name": "ntp-servers", "data": "10.1.10.1", "source": "site home", "provided": True,
              "fabric_overridden": True, "overrides": ["fabric"]},
             {"code": 114, "name": "v4-captive-portal", "data": "https://portal.home.arpa/", "source": "organisation",
              "provided": False, "fabric_overridden": False, "overrides": []}],
    "classes": [{"name": "fabric-nb-s5-ipxe", "owner": "netboot", "test": "substring(option[77].hex,0,4) == 'iPXE'",
                 "fields": {"boot_file_name": "http://boot.home.arpa/boot.ipxe"},
                 "rows": [{"code": 67, "name": "boot-file-name", "data": "http://boot.home.arpa/boot.ipxe",
                           "overridden_by": "", "overrides": []}]}],
}
