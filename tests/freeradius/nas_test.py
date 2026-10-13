#!/usr/bin/env python3
"""Vendor profiles for RADIUS clients (manual 1.11.1.2, 1.11.1.3; decisions 2.1.11.4, 2.1.11.5), pure logic, no
containers: the profiles, the client settings (vendor, transport) and their refusals, what the policy gets per client,
MAB read in each vendor's shape, the VLAN attributes, the Cisco configuration (never the secret), RadSec's relaxation.

    python3 tests/freeradius/nas_test.py
"""
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.join(REPO, "src", "containers", "freeradius")]
from check_mab import check_mab  # noqa: E402
from vlan_reply import vlan_reply  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.radius.nas.cisco_snippet import SECRET_PLACEHOLDER, cisco_snippet  # noqa: E402
from fabriclib.radius.nas.nas_profile import nas_profile  # noqa: E402
from fabriclib.radius.nas.policy_clients import policy_clients  # noqa: E402
from fabriclib.radius.normalize_radius_clients import normalize_radius_clients  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402

FAILED = 0
SECRET = "Sw1tchSecretForTests0123456789ab"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


def refused(fn, *args):
    try:
        fn(*args)
    except ValidationError as exc:
        return str(exc)
    return ""


# ------------------------------------------------------------------ profiles
check("profiles: unifi, cisco, generic; only Cisco offers RadSec and CoA (UDP 3799)",
      [nas_profile(v)["radsec"] for v in ("unifi", "cisco", "generic")] == [False, True, False]
      and nas_profile("cisco")["coa"]["port"] == 3799 and not nas_profile("unifi")["coa"]
      and "UniFi does not document" in nas_profile("UniFi")["no_coa"])
check("profiles: an unknown vendor is refused, never treated as generic",
      refused(nas_profile, "juniper") == "vendor must be one of unifi, cisco, generic")

# ------------------------------------------------------------------ client settings
clients, embedded = normalize_radius_clients([
    {"name": "old-switch", "address": "192.168.4.2"},
    {"name": "Unifi-SW", "address": "192.168.4.3", "vendor": "UniFi", "secret": SECRET},
    {"name": "core-sw", "address": "192.168.4.4", "vendor": "cisco", "transport": "RadSec"}])
# covers: setting:radius_clients +
check("radius_clients: a client from before 0.9 is generic on RADIUS/UDP; vendor and transport kept, lower-cased",
      [(c["name"], c["vendor"], c["transport"]) for c in clients]
      == [("old-switch", "generic", "udp"), ("unifi-sw", "unifi", "udp"), ("core-sw", "cisco", "radsec")]
      and embedded == {"unifi-sw": SECRET}, clients)
# covers: setting:radius_clients -
check("radius_clients refused: an unknown vendor, a transport that is not one, RadSec for UniFi and for generic",
      refused(normalize_radius_clients, [{"name": "a", "address": "10.0.0.1", "vendor": "aruba"}])
      == "radius_clients: a: vendor must be one of unifi, cisco, generic"
      and "transport must be one of udp, radsec"
      in refused(normalize_radius_clients, [{"name": "a", "address": "10.0.0.1", "transport": "tls"}])
      and "RadSec is not offered for vendor unifi"
      in refused(normalize_radius_clients, [{"name": "a", "address": "10.0.0.1", "vendor": "unifi",
                                             "transport": "radsec"}])
      and "RadSec is not offered for vendor generic"
      in refused(normalize_radius_clients, [{"name": "a", "address": "10.0.0.1", "transport": "radsec"}]))

pc = policy_clients(clients)
check("the policy gets each client's vendor rules: Cisco MAB is Call-Check, UniFi's password is the MAC",
      pc["core-sw"]["mab"] == {"service_type": "Call-Check", "password_is_mac": False}
      and pc["unifi-sw"]["mab"]["password_is_mac"] and pc["old-switch"]["vendor"] == "generic"
      and all(p["vlan"] == "rfc3580" for p in pc.values()), pc)

# ------------------------------------------------------------------ MAB in each vendor's shape
CISCO, UNIFI, GENERIC = pc["core-sw"]["mab"], pc["unifi-sw"]["mab"], pc["old-switch"]["mab"]
mac = "02:00:00:00:30:01"
check("MAB, Cisco: Call-Check, User-Name aabbccddeeff, Calling-Station-Id AA-BB-.. -> the MAC",
      check_mab({"Service-Type": "Call-Check", "User-Name": "020000003001", "User-Password": "020000003001",
                 "Calling-Station-Id": "02-00-00-00-30-01"}, CISCO) == (mac, "")
      and check_mab({"Service-Type": "10", "User-Name": "020000003001"}, CISCO) == (mac, ""))
check("MAB, Cisco: without Call-Check (a password login pretending to be MAB) refused",
      check_mab({"Service-Type": "Framed-User", "User-Name": "020000003001"}, CISCO)
      == (None, "not_a_MAB_request_for_this_switch")
      and check_mab({"User-Name": "020000003001"}, CISCO) == (None, "not_a_MAB_request_for_this_switch"))
check("MAB, UniFi: MAC as user name and password (AABBCCDDEEFF) -> the MAC; another password refused",
      check_mab({"User-Name": "020000003001", "User-Password": "020000003001",
                 "Calling-Station-Id": "02-00-00-00-30-01"}, UNIFI) == (mac, "")
      and check_mab({"User-Name": "020000003001", "User-Password": "hunter2-hunter2"}, UNIFI)
      == (None, "password_is_not_the_MAC"))
check("MAB, every vendor: a User-Name that is not a MAC, or not the calling MAC, refused",
      all(check_mab({"Service-Type": "Call-Check", "User-Name": "alice"}, r)[1] == "user_name_is_not_a_MAC"
          for r in (CISCO, UNIFI, GENERIC))
      and all(check_mab({"Service-Type": "Call-Check", "User-Name": mac, "Calling-Station-Id": "02:00:00:00:99:99"},
                        r)[1] == "user_name_is_not_the_calling_MAC" for r in (CISCO, UNIFI, GENERIC)))
check("MAB, generic (and a client the policy does not know): any MAC spelling",
      check_mab({"User-Name": "0200.0000.3001"}, GENERIC) == (mac, "") and check_mab({"User-Name": mac}, None)
      == (mac, ""))

# ------------------------------------------------------------------ VLAN attributes
check("VLAN reply (RFC 3580, what UniFi, Cisco and generic switches take): Tunnel-Type VLAN, IEEE-802, the id; "
      "nothing without a VLAN",
      vlan_reply(30) == (("Tunnel-Type", ":=", "VLAN"), ("Tunnel-Medium-Type", ":=", "IEEE-802"),
                         ("Tunnel-Private-Group-Id", ":=", "30")) and vlan_reply(None) == () and vlan_reply(0) == ())

# ------------------------------------------------------------------ the Cisco configuration
V = {"host_ip": "192.168.4.10", "hostname_radius": "radius.lan.example"}
udp = cisco_snippet(V, {"name": "core-sw", "transport": "udp"})
tls = cisco_snippet(V, {"name": "core-sw", "transport": "radsec"})
check("Cisco configuration, RADIUS/UDP: fabric's address and ports, accounting, CoA on 3799 from fabric, the "
      "secret only as a placeholder",
      "address ipv4 192.168.4.10 auth-port 1812 acct-port 1813" in udp and f" key {SECRET_PLACEHOLDER}" in udp
      and "aaa accounting dot1x default start-stop group FABRIC" in udp and " port 3799" in udp
      and f"client 192.168.4.10 server-key {SECRET_PLACEHOLDER}" in udp and SECRET not in udp, udp)
check("Cisco configuration, RadSec: TCP 2083, the switch's own key, CN radsec-<name>, the server name matched, "
      "the TLS secret 'radsec'",
      "auth-port 2083 acct-port 2083" in tls and "subject-name CN=radsec-core-sw" in tls
      and "tls match-server-identity hostname radius.lan.example" in tls and " key radsec" in tls
      and "crypto pki enroll fabric-radsec" in tls, tls)

# ------------------------------------------------------------------ RadSec's relaxation, in status
rel = relaxed_settings({"install_freeradius": True, "radius_clients": clients}, config_dir=REPO + "/no-such-dir",
                       daemon_json=REPO + "/no-such-file")
names = [r["setting"] for r in rel]
check("relaxed settings: each client on RADIUS/UDP is listed (MD5 only), a RadSec client is not",
      "radius_clients: old-switch on RADIUS/UDP" in names and "radius_clients: unifi-sw on RADIUS/UDP" in names
      and not any("core-sw" in n for n in names), names)
check("relaxed settings: nothing for RADIUS while 802.1X is off",
      not any("radius" in r["setting"] for r in relaxed_settings({"install_freeradius": False,
                                                                     "radius_clients": clients},
                                                                    config_dir=REPO + "/no-such-dir",
                                                                    daemon_json=REPO + "/no-such-file")))

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
