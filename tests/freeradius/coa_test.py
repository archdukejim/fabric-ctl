#!/usr/bin/env python3
"""Sessions, Disconnect and CoA (manual 1.11.1.4; decisions 2.1.11.6, 2.1.11.8), without containers: the packets
fabric signs (RFC 5176) against a stand-in switch on the loopback (nas_standin.py, written from the RFC), the sessions
read from accounting lines, every refusal (a vendor without CoA, a closed session, a NAS outside the client, no
secret, a switch that refuses, does not answer or answers with another secret), and who may do it (radius:coa).

    python3 tests/freeradius/coa_test.py
"""
import datetime
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path[0:0] = [os.path.join(REPO, "src"), os.path.dirname(os.path.abspath(__file__))]
from nas_standin import NasStandin  # noqa: E402
import fabriclib.radius.coa.coa_session as coa_mod  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.radius.coa.attributes import cisco_avpair  # noqa: E402
from fabriclib.radius.coa.build_radius_packet import build_radius_packet  # noqa: E402
from fabriclib.radius.coa.read_radius_reply import read_radius_reply  # noqa: E402
from fabriclib.radius.coa.send_coa import send_coa  # noqa: E402
from fabriclib.radius.list_radius_sessions import list_radius_sessions  # noqa: E402
from fabriclib.radius.radius_sessions import radius_sessions  # noqa: E402
from fabriclib.rbac.permissions import BUNDLES  # noqa: E402
from fabriclib.rbac.required_permission import required_permission  # noqa: E402

FAILED = 0
SECRET = "Sw1tchSecretForTests0123456789ab"
AUDIT = []
coa_mod.write_audit = lambda *a, **k: AUDIT.append(a)       # the audit log, stood in for


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[-700:]}"))


T0 = datetime.datetime(2026, 10, 12, 9, 0, 0)


def at(minutes, msg):
    return T0 + datetime.timedelta(minutes=minutes), msg


RECORDS = [
    at(0, "fabric: ACCEPT method=eap-tls device=laptop1 vlan=20 mac=02:00:00:00:10:01 nas=core client=core-sw"),
    at(1, "fabric: ACCT client=core-sw mac=02:00:00:00:10:01 status=Start session=0A0B0C0D00000012 nas_ip=127.0.0.1 "
          "port=GigabitEthernet1%2F0%2F7 user=laptop1 ip=-"),
    at(2, "fabric: ACCT client=unifi-sw mac=02:00:00:00:20:01 status=Start session=5F3A9C01-00000007 "
          "nas_ip=192.168.4.3 port=- user=alice ip=-"),
    at(3, "fabric: ACCT client=core-sw mac=02:00:00:00:10:02 status=Start session=GONE1 nas_ip=127.0.0.1 port=Gi1 "
          "user=x ip=-"),
    at(4, "fabric: ACCT client=core-sw mac=02:00:00:00:10:02 status=Stop session=GONE1 nas_ip=127.0.0.1 port=Gi1 "
          "user=x ip=-"),
    at(5, "fabric: ACCT client=core-sw mac=02:00:00:00:10:01 status=Interim-Update session=0A0B0C0D00000012 "
          "nas_ip=127.0.0.1 port=GigabitEthernet1%2F0%2F7 user=laptop1 ip=10.20.0.5"),
    at(6, "fabric: ACCT client=core-sw mac=02:00:00:00:10:03 status=Start session=FAR1 nas_ip=10.9.9.9 port=Gi2 "
          "user=y ip=-"),
    at(7, "fabric: ACCT client=generic-sw mac=02:00:00:00:10:04 status=Start session=G1 nas_ip=192.168.4.9 port=3 "
          "user=z ip=-"),
]
V = {"install_freeradius": True,
     "radius_clients": [{"name": "core-sw", "address": "127.0.0.0/8", "vendor": "cisco", "transport": "radsec"},
                        {"name": "unifi-sw", "address": "192.168.4.3", "vendor": "unifi", "transport": "udp"},
                        {"name": "generic-sw", "address": "192.168.4.9", "vendor": "generic", "transport": "udp"}]}
SECRETS = {"radius_secrets": {"core-sw": SECRET, "unifi-sw": SECRET, "generic-sw": SECRET}}

# ------------------------------------------------------------------ packets (RFC 5176)
pkt = build_radius_packet(43, 7, SECRET, [(44, b"0A0B"), (26, cisco_avpair("subscriber:command=reauthenticate"))])
nas = NasStandin(SECRET)
reply = send_coa("127.0.0.1", nas.port, SECRET, 43, [(44, b"0A0B")], timeout=1, tries=1)
check("a CoA-Request as fabric signs it is valid to a switch that knows the secret (Request Authenticator, "
      "Message-Authenticator), and its CoA-ACK is read as one",
      nas.received and nas.received[-1]["valid"] and reply == {"ack": True, "code": 44, "error_cause": None,
                                                                 "error": ""}, (nas.received, reply))
check("the Cisco-AVPair is vendor 9, type 1, the command as text",
      pkt.find(b"\x1a\x29\x00\x00\x00\x09\x01\x23subscriber:command=reauthenticate") > 0, pkt)
nas.stop()
nas = NasStandin("Another-Secret-On-The-Switch-01")
reply = send_coa("127.0.0.1", nas.port, SECRET, 40, [(44, b"0A0B")], timeout=1, tries=1)
check("a switch with another secret: it refuses the packet, and its answer (signed with its own secret) is reported "
      "as not signed with this client's secret",
      not nas.received[-1]["valid"] and reply and not reply["ack"]
      and "not signed with this client's secret" in reply["error"], (nas.received, reply))
nas.stop()
fake = build_radius_packet(40, 9, SECRET, [(44, b"x")])
try:
    read_radius_reply(bytes([41, 8, 0, 20]) + bytes(16), fake, SECRET)
    other_id = False
except ValueError as exc:
    other_id = "another request" in str(exc)
check("an answer with another identifier is not taken as the answer", other_id)

# ------------------------------------------------------------------ sessions from accounting
found = list_radius_sessions(RECORDS)
by_id = {s["session"]: s for s in found}
check("sessions: open ones only (a Stop ends one), the latest record wins, who and VLAN from the ACCEPT for its MAC, "
      "values unquoted",
      set(by_id) == {"0A0B0C0D00000012", "5F3A9C01-00000007", "FAR1", "G1"}
      and by_id["0A0B0C0D00000012"]["status"] == "Interim-Update" and by_id["0A0B0C0D00000012"]["who"] == "laptop1"
      and by_id["0A0B0C0D00000012"]["vlan"] == "20" and by_id["0A0B0C0D00000012"]["port"] == "GigabitEthernet1/0/7"
      and by_id["0A0B0C0D00000012"]["since"] == "2026-10-12T09:01:00", found)
gone = list_radius_sessions(RECORDS + [at(9, "fabric: ACCT client=core-sw mac=- status=Accounting-On session=- "
                                              "nas_ip=127.0.0.1 port=- user=- ip=-")])
check("sessions: a client's Accounting-On (it restarted) ends all its sessions",
      {s["session"] for s in gone} == {"5F3A9C01-00000007", "G1"}, gone)
view = radius_sessions(V, RECORDS)
acts = {s["session"]: (s["actions"], s["no_coa"][:26]) for s in view["sessions"]}
# covers: cli:radius.sessions agent:get.radius.sessions +
check("the Sessions view: Cisco sessions offer disconnect, reauthenticate and bounce; UniFi's and generic's none, "
      "with why", acts["0A0B0C0D00000012"] == (["bounce", "disconnect", "reauthenticate"], "")
      and acts["5F3A9C01-00000007"] == ([], "UniFi does not document RA") and acts["G1"][0] == [], acts)

# ------------------------------------------------------------------ coa_session: sent and acknowledged
nas = NasStandin(SECRET, port=0)
cisco = dict(coa_mod.nas_profile("cisco"))
real_profile = coa_mod.nas_profile
coa_mod.nas_profile = lambda v: dict(real_profile(v), coa=dict(cisco["coa"], port=nas.port)) if v == "cisco" \
    else real_profile(v)                    # the stand-in listens on a free port, not 3799
for action, code in (("disconnect", 40), ("reauthenticate", 43), ("bounce", 43)):
    res = coa_mod.coa_session(V, "alice", action, "core-sw", "0A0B0C0D00000012", "web", SECRETS, RECORDS)
    got = nas.received[-1] if nas.received else {}
    # covers: cli:radius.disconnect cli:radius.reauthenticate agent:post.radius.sessions.disconnect +
    # covers: agent:post.radius.sessions.reauthenticate +
    check(f"{action}: sent to the session's switch as code {code}, naming the session (Acct-Session-Id, "
          "Calling-Station-Id, NAS-IP-Address), acknowledged, audited",
          got.get("code") == code and got.get("valid") and got["attrs"][44] == [b"0A0B0C0D00000012"]
          and got["attrs"][31] == [b"02-00-00-00-10-01"] and got["attrs"][4] == [bytes([127, 0, 0, 1])]
          and "acknowledged" in res["message"] and AUDIT[-1][1] == "RADIUS_COA" and "result=ACK" in AUDIT[-1][2]
          and (action == "disconnect" or (b"subscriber:command=" + (b"bounce-host-port" if action == "bounce"
                                                                     else b"reauthenticate")) in got["attrs"][26][0]),
          (got, res, AUDIT[-1:]))
nas.stop()


def refusal(*args, records=RECORDS, secrets=SECRETS, v=V):
    sent = []
    before = len(AUDIT)
    try:
        coa_mod.coa_session(v, "alice", *args, "web", secrets, records,
                            sender=lambda *a: sent.append(a) or {"ack": True, "code": 44, "error_cause": None,
                                                                 "error": ""})
    except ValidationError as exc:
        return str(exc), sent, len(AUDIT) - before
    return "", sent, len(AUDIT) - before


msg, sent, audited = refusal("disconnect", "unifi-sw", "5F3A9C01-00000007")
# covers: cli:radius.disconnect agent:post.radius.sessions.disconnect -
check("refused for a UniFi switch: why (UniFi documents no CoA) and what to do instead; nothing sent",
      "UniFi does not document RADIUS CoA" in msg and "Reconnect" in msg and not sent and not audited, msg)
msg, sent, _ = refusal("reauthenticate", "generic-sw", "G1")
# covers: cli:radius.reauthenticate agent:post.radius.sessions.reauthenticate -
check("refused for a generic switch: why, nothing sent", "does not know whether this switch accepts CoA" in msg
      and not sent, msg)
for args, want in ((("disconnect", "core-sw", "GONE1"), "no open session GONE1 on core-sw"),
                   (("disconnect", "core-sw", "FAR1"), "is not core-sw's address"),
                   (("disconnect", "ghost", "X"), "no RADIUS client ghost"),
                   (("shutdown", "core-sw", "0A0B0C0D00000012"), "action must be one of")):
    msg, sent, _ = refusal(*args)
    check(f"refused, nothing sent: {want}", want in msg and not sent, msg)
msg, sent, _ = refusal("disconnect", "core-sw", "0A0B0C0D00000012", secrets={"radius_secrets": {}})
check("refused, nothing sent: a client without a shared secret", "has no shared secret" in msg and not sent, msg)
msg, sent, _ = refusal("disconnect", "core-sw", "0A0B0C0D00000012", v={**V, "install_freeradius": False})
check("refused, nothing sent: 802.1X off", "802.1X is off" in msg and not sent, msg)

coa_mod.nas_profile = real_profile
for answer, want in (("nak", "core-sw refused Disconnect: Session Context Not Found"),
                     ("silent", "did not answer on UDP")):
    nas = NasStandin(SECRET, answer=answer)
    coa_mod.nas_profile = lambda v, p=nas.port: dict(real_profile(v), coa=dict(cisco["coa"], port=p)) \
        if v == "cisco" else real_profile(v)
    coa_mod.send_coa.__defaults__ = (1, 1)                      # a short wait for the test
    try:
        coa_mod.coa_session(V, "alice", "disconnect", "core-sw", "0A0B0C0D00000012", "web", SECRETS, RECORDS)
        msg = ""
    except ValidationError as exc:
        msg = str(exc)
    nas.stop()
    coa_mod.nas_profile = real_profile
    check(f"the switch {'refuses (NAK)' if answer == 'nak' else 'does not answer'}: said so, audited with the result",
          want in msg and AUDIT[-1][1] == "RADIUS_COA" and ("result=NAK" in AUDIT[-1][2] or answer == "silent"),
          (msg, AUDIT[-1:]))

# ------------------------------------------------------------------ who may (2.1.11.8)
check("the routes: sessions need radius:read, Disconnect and CoA radius:coa, a client's vendor radius:admin",
      required_permission("GET", ["radius", "sessions"]) == "radius:read"
      and required_permission("POST", ["radius", "sessions", "disconnect"]) == "radius:coa"
      and required_permission("POST", ["radius", "sessions", "reauthenticate"]) == "radius:coa"
      and required_permission("POST", ["radius", "clients", "sw1", "set"]) == "radius:admin"
      and required_permission("POST", ["radius", "sessions", "shutdown"]) is None)
# covers: agent:post.radius.sessions.disconnect agent:post.radius.sessions.reauthenticate -
check("radius:coa: in the Admin and Equipment operator bundles only (an auditor, a network operator, the helpdesk "
      "may not cut a device off)",
      "radius:coa" in BUNDLES["admin"] and "radius:coa" in BUNDLES["fabric-equipment-operator"]
      and not any("radius:coa" in BUNDLES[b] for b in ("fabric-auditor", "fabric-network-operator",
                                                       "fabric-helpdesk", "fabric-pki-operator")))

print(f"\n{'FAILED' if FAILED else 'all passed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
