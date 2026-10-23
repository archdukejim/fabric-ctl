#!/usr/bin/env python3
"""DHCP names left behind for addresses named by hand (decision 2.1.10.22, manual 1.10.4.20), with no container: the
addresses set by hand (hand_set_addresses), kept for the hourly timer (keep_hand_set_addresses, root's 0600 file), the
records of DHCP's zone left behind for them (stale_dhcp_names over zone_records), their deletion in one signed update
with nsupdate and BIND's container stood in for (clear_stale_dhcp_names: nothing sent when nothing is stale, refused
without Kea's key or when BIND refuses, nothing audited then), and `fabricctl dhcp clean-names`. Kea's key is the one
made at install (its yearly replacement, 2.1.10.42, is open). Against a real BIND and Kea: tests/kea/run.py.

    python3 tests/dhcp/clean_names_test.py
"""
import io
import json
import os
import stat
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
import fabriclib.dhcp.clean_dhcp_names as m_clean  # noqa: E402
import fabriclib.dhcp.clear_stale_dhcp_names as m_clear  # noqa: E402
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.dhcp.hand_set_addresses import hand_set_addresses  # noqa: E402
from fabriclib.dhcp.keep_hand_set_addresses import keep_hand_set_addresses  # noqa: E402
from fabriclib.dhcp.run_dhcp_command import run_dhcp_command  # noqa: E402
from fabriclib.dhcp.stale_dhcp_names import stale_dhcp_names  # noqa: E402
from fabriclib.dns.common.zone_records import zone_records  # noqa: E402

FAILED = 0


def check(name, ok, detail=""):
    global FAILED
    FAILED += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))


def why(fn):
    try:
        fn()
    except ValidationError as e:
        return str(e)
    return "not refused"


W = tempfile.mkdtemp(prefix="fabric-clean-names-")
V = {"install_kea": True, "domain": "lan.test", "deploy_base_dir": W, "host_ip": "192.168.4.2",
     "dhcp": {"ddns": True},
     "dns": {"dynamic_zone_var": {"A": [{"name": "printer", "ip": "10.1.20.42"}, {"name": "bad", "ip": "nope"}],
                                  "AAAA": [{"name": "nas6", "ip": "fd00:0:0::9"}]},
             "lab.test": {"A": [{"name": "cam", "ip": "10.1.20.44"}]},
             "20.1.10.in-addr.arpa": {"A": [{"name": "x", "ip": "10.9.9.9"}]}}}
ZONE = """$ORIGIN dhcp.lan.test.
$TTL 300
@   IN SOA ns.lan.test. root.lan.test. (
        1 3600 600 86400 300 )
    NS  ns.lan.test.
printer     A      10.1.20.42
            DHCID  AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=
laptop      300 IN A 10.1.20.120
            DHCID  AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No=
both        A      10.1.20.44
both        A      10.1.20.130
both        DHCID  AAIBdGVzdA==
v6          AAAA   fd00::9
"""

print("--- the addresses set by hand and what DHCP left for them")
check("the forward zones' A and AAAA addresses, canonical; a reverse zone and an unreadable address left out",
      hand_set_addresses(V) == ["10.1.20.42", "10.1.20.44", "fd00::9"], hand_set_addresses(V))
recs = zone_records(ZONE, "dhcp.lan.test", {"A", "AAAA", "DHCID"})
check("zone_records: owners made absolute, a left-out owner repeating the last, TTL and class skipped, the SOA's "
      "parentheses skipped", ("printer.dhcp.lan.test.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=")
      in recs and ("laptop.dhcp.lan.test.", "A", "10.1.20.120") in recs and not any(r[1] == "SOA" for r in recs), recs)
stale = stale_dhcp_names(ZONE, "dhcp.lan.test", hand_set_addresses(V))
check("left behind: the address records of names set by hand, and a name's DHCID once none of its addresses is "
      "left; a name with another address keeps its DHCID; laptop untouched; an AAAA in any form",
      stale == [("printer.dhcp.lan.test.", "A", "10.1.20.42"),
                ("printer.dhcp.lan.test.", "DHCID", "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="),
                ("both.dhcp.lan.test.", "A", "10.1.20.44"),
                ("v6.dhcp.lan.test.", "AAAA", "fd00::9")], stale)
check("nothing set by hand: nothing left behind", stale_dhcp_names(ZONE, "dhcp.lan.test", []) == [])

print("--- kept for the hourly timer")
path = keep_hand_set_addresses(V)
check("written root's 0600 next to Kea's folders, with the addresses", path == os.path.join(W, "kea", "hand-set.json")
      and stat.S_IMODE(os.stat(path).st_mode) == 0o600
      and json.load(open(path))["addresses"] == hand_set_addresses(V), path)
check("DHCP's DNS registration off: nothing kept, an earlier file removed",
      keep_hand_set_addresses({**V, "dhcp": {"ddns": False}}) is None and not os.path.exists(path))

print("--- the deletion, nsupdate and BIND's container stood in for")
SENT, AUDIT = [], []
m_clear._served_zone = lambda zone: ZONE
m_clear.write_audit = lambda actor, event, detail, source, path=None: AUDIT.append((event, detail, source))


class Done:
    def __init__(self, code, out=""):
        self.returncode, self.stdout, self.stderr = code, out, ""


def nsupdate(code):
    def run(argv, input="", capture_output=True, text=True, timeout=30):
        key = open(argv[2]).read()
        SENT.append((argv[:2], input, key, stat.S_IMODE(os.stat(argv[2]).st_mode), argv[2]))
        return Done(code, "update failed: REFUSED" if code else "")
    return run


m_clear.subprocess.run = nsupdate(0)
check("nothing to delete: nothing sent", m_clear.clear_stale_dhcp_names(V, ["10.9.9.9"], "s3cret", "root", "apply")
      == [] and SENT == [])
check("refused: Kea's key without a secret", "has no secret" in why(
    lambda: m_clear.clear_stale_dhcp_names(V, hand_set_addresses(V), "", "root", "apply")) and SENT == [])
gone = m_clear.clear_stale_dhcp_names(V, hand_set_addresses(V), "s3cret", "root", "apply")
argv, script, key, mode, keyfile = SENT[-1]
check("one update to this host's BIND: each address record, a name's whole DHCID set; the key in a 0600 file, never "
      "on the command line, removed after", argv == ["nsupdate", "-k"] and "server 192.168.4.2 53" in script
      and "zone dhcp.lan.test" in script and "update delete printer.dhcp.lan.test. A 10.1.20.42" in script
      and "update delete printer.dhcp.lan.test. DHCID" in script and "both.dhcp.lan.test. DHCID" not in script
      and script.rstrip().endswith("send") and "s3cret" in key and mode == 0o600 and not os.path.exists(keyfile)
      and gone == stale, (script, mode))
check("each removal audited as the apply's", [a[0] for a in AUDIT] == ["DHCP_NAME_CLEAR"] * 4
      and all(a[2] == "apply" for a in AUDIT), AUDIT)
m_clear.subprocess.run = nsupdate(2)
n = len(AUDIT)
check("refused: BIND refusing the update, saying nothing was deleted; nothing audited", "nothing was deleted" in why(
    lambda: m_clear.clear_stale_dhcp_names(V, hand_set_addresses(V), "s3cret", "root", "cli"))
    and len(AUDIT) == n and not os.path.exists(SENT[-1][4]))
check("Kea or its DNS registration off: nothing read, nothing sent",
      m_clear.clear_stale_dhcp_names({**V, "install_kea": False}, ["10.1.20.42"], "s", "root", "cli") == []
      and m_clear.clear_stale_dhcp_names({**V, "dhcp": {"ddns": False}}, ["10.1.20.42"], "s", "root", "cli") == [])


def cli(v, *argv):
    o, e = io.StringIO(), io.StringIO()
    with redirect_stdout(o), redirect_stderr(e):
        code = run_dhcp_command(v, list(argv))
    return code, o.getvalue() + e.getvalue()


print("--- fabricctl dhcp clean-names")
m_clear.subprocess.run = nsupdate(0)
m_clean.load_secrets = lambda: {"kea_ddns_secret": "s3cret"}
# covers: cli:dhcp.clean-names +
keep_hand_set_addresses(V)
code, text = cli(V, "clean-names", "--scheduled")
check("the timer's run: the names left behind deleted from the kept addresses, audited as the timer's (exit 0)",
      code == 0 and "4 record(s) deleted" in text and AUDIT[-1][2] == "timer", (code, text))
code, text = cli({**V, "install_kea": False}, "clean-names")
check("DHCP off: nothing to clean, said (exit 0)", code == 0 and "nothing to clean" in text, text)
# covers: cli:dhcp.clean-names -
os.remove(os.path.join(W, "kea", "hand-set.json"))
code, text = cli(V, "clean-names")
check("refused: no apply has kept the addresses yet, saying to apply (exit 1)", code == 1
      and "no apply has kept" in text, text)
code, text = cli(V, "clean-names", "now")
check("a stray argument: the usage (exit 2)", code == 2 and "clean-names" in text, code)
code, text = cli(V, "clean-names", "--subnet", "x")
check("a flag it does not take: the usage (exit 2)", code == 2, code)

print(f"\n{FAILED} failed" if FAILED else "\nall passed")
sys.exit(1 if FAILED else 0)
