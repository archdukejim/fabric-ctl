"""The address plan's store in AD, its pure parts (manual 1.10.4.32, 1.10.4.33; 2.1.10.34, 2.1.10.35): where each
entry's DN is (a VLAN `CN=<site>/vlan/<id>`, a subnet `CN=<site>/<name>` in the domain's OU=networks, a range, an
address and a scan request below its subnet, a site's record in CN=sites,CN=fabric,CN=System), every name escaped;
the positional values the option lists are kept in, round trip; a netboot preset kept apart from the options; and
write_plan's and write_scan_request's refusals before AD is asked. Pure logic, no container: Samba's ldb is a stand-in
that builds DNs as ldb.Dn does; the real DC's run is tests/samba/plan_store.py.
    python3 tests/samba/plan_store_test.py"""
import os
import sys
import traceback
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))

PASS = FAIL = 0


def _escape(value):
    """Purpose: an RDN value escaped as ldb.Dn.set_component escapes it (RFC 4514's specials).
    Inputs:  value — str.
    Returns: str.
    Fails:   never.
    Feeds:   _Dn."""
    out = "".join("\\" + c if c in ',+"\\<>;=' else c for c in value)
    return ("\\" + out) if out[:1] in ("#", " ") else out


class _Dn:
    """A stand-in for ldb.Dn: its text, its first component replaceable, its parent."""

    def __init__(self, samdb, text):
        self.text = str(text)

    def set_component(self, i, name, value):
        """Replace the first component (the only one fabric replaces)."""
        rest = self.text.split(",", 1)[1]
        self.text = f"{name}={_escape(value)},{rest}"

    def __str__(self):
        return self.text


class _Samdb:
    """A stand-in SamDB: its domain's DN, and nothing in it."""

    def domain_dn(self):
        return "DC=ad,DC=test"

    def search(self, **kw):
        raise AssertionError("AD was asked")


ldb = types.ModuleType("ldb")
ldb.Dn = _Dn
ldb.LdbError = type("LdbError", (Exception,), {})
ldb.ERR_NO_SUCH_OBJECT = 32
sys.modules["ldb"] = ldb
import paths  # noqa: E402
from read_plan import listed, split_netboot  # noqa: E402
from write_plan import entry_dn, values_of, write_plan  # noqa: E402
from write_scan_request import request_dn, write_scan_request  # noqa: E402


def check(name, ok, detail=""):
    """Purpose: record one check and print it.
    Inputs:  name — what is checked; ok — bool; detail — shown when it fails.
    Returns: None.
    Fails:   never.
    Feeds:   main."""
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(fn, words):
    """Purpose: whether fn() raises a ValueError naming `words`.
    Inputs:  fn — callable; words — text the message must hold.
    Returns: bool.
    Fails:   never.
    Feeds:   main."""
    try:
        fn()
    except ValueError as e:
        return words in str(e)
    return False


def main():
    """Purpose: the checks, positive and negative.
    Inputs:  none.
    Returns: None.
    Fails:   never (a crash is counted by the caller).
    Feeds:   this script."""
    s = _Samdb()
    nets = "OU=networks,DC=ad,DC=test"
    check("a VLAN is CN=<site>/vlan/<id> in the domain's OU=networks",
          str(entry_dn(s, {"what": "vlan", "site": "lan", "key": 20})) == f"CN=lan/vlan/20,{nets}")
    check("a subnet is CN=<site>/<name>",
          str(entry_dn(s, {"what": "subnet", "site": "lan", "key": "iot"})) == f"CN=lan/iot,{nets}")
    check("a range and an address are below their subnet's entry",
          str(entry_dn(s, {"what": "range", "site": "lan", "key": "dhcp-10.1.20.100", "subnet": "iot"}))
          == f"CN=dhcp-10.1.20.100,CN=lan/iot,{nets}"
          and str(entry_dn(s, {"what": "address", "site": "lan", "key": "10.1.20.5", "subnet": "iot"}))
          == f"CN=10.1.20.5,CN=lan/iot,{nets}")
    check("a name with a comma or a plus is escaped, never a second component",
          str(entry_dn(s, {"what": "subnet", "site": "lan", "key": "a,b+c"})) == f"CN=lan/a\\,b\\+c,{nets}")
    check("a site's record is CN=<site>,CN=sites,CN=fabric,CN=System; the domain's set beside it",
          str(paths.site_record_dn(s, "lan")) == "CN=lan,CN=sites,CN=fabric,CN=System,DC=ad,DC=test"
          and paths.domain_options_dn(s) == "CN=dhcp-options,CN=fabric,CN=System,DC=ad,DC=test")
    check("a scan request is below its subnet's entry",
          str(request_dn(s, "lan", "iot", "scan-20261023120000-a1b2c3"))
          == f"CN=scan-20261023120000-a1b2c3,CN=lan/iot,{nets}")

    opts = [{"name": "domain-name-servers", "data": "10.1.0.1"}, {"code": 66, "data": "boot.lan"}]
    check("values: booleans TRUE/FALSE, nothing for empty, a list one JSON object per value with its position",
          values_of(True) == ["TRUE"] and values_of(False) == ["FALSE"] and values_of("") == []
          and values_of(None) == [] and values_of([]) == [] and values_of(7) == ["7"]
          and values_of(opts)[0].startswith("0:{") and values_of(opts)[1].startswith("1:{"))
    check("a list read back in its positions' order, whatever order LDAP returns",
          listed(list(reversed(values_of(opts)))) == opts)
    check("a value that is not <n>:<JSON> is skipped", listed(["x", "1:{bad", "0:{\"a\": 1}"]) == [{"a": 1}])
    boot = {"server": "10.1.0.9", "bios": "pxelinux.0"}
    check("a netboot preset kept apart from the options",
          split_netboot(opts + [{"netboot": boot}]) == (opts, boot) and split_netboot(opts) == (opts, None))

    # refusals, before AD is asked (the stand-in fails the check if it is)
    check("negative: an unknown change is refused", refused(
        lambda: write_plan(s, None, "lan", [{"do": "add", "what": "local_scan", "site": "lan"}]), "unknown plan change"))
    check("negative: an unknown verb is refused", refused(
        lambda: write_plan(s, None, "lan", [{"do": "move", "what": "vlan", "site": "lan"}]), "unknown plan change"))
    check("negative: a change naming no site is refused", refused(
        lambda: write_plan(s, None, "lan", [{"do": "add", "what": "vlan", "key": 10}]), "names no site"))
    check("negative: a range naming no subnet is refused", refused(
        lambda: write_plan(s, None, "lan", [{"do": "add", "what": "range", "site": "lan", "key": "x"}]),
        "names no subnet"))
    check("negative: a scan request id fabric does not make is refused", refused(
        lambda: write_scan_request(s, None, "lan", "add", "lan", "iot", "../x", {"cidr": "10.1.20.0/24"}),
        "not a scan request's id"))
    check("negative: a scan request naming no subnet is refused", refused(
        lambda: write_scan_request(s, None, "lan", "add", "lan", "", "scan-20261023120000-a1b2c3", {}),
        "names its site and its subnet"))


if __name__ == "__main__":
    try:
        main()
    except Exception:  # a crash is a failure, and the summary still prints
        FAIL += 1
        traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
