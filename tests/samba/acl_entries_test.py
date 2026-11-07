"""Access entries on objects a search just found (2.3.6.29): with gone_ok, an object deleted since the search (a site's
join account its new DC deletes while the root converges) is skipped; without it, or for any other refusal, the error
stands. Samba's ldb, SDUtils and security are stand-ins; the real DCs' run is tests/samba/site_join.py.
    python3 tests/samba/acl_entries_test.py"""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))


class LdbError(Exception):
    """ldb.LdbError's stand-in: args (code, text)."""


GONE = "CN=fabric-join-edge,OU=people,DC=ad,DC=test"


class Ace:
    def __init__(self, text):
        self.text = text


class Sd:
    def __init__(self):
        self.dacl = types.SimpleNamespace(aces=[])


class SDUtils:
    """Reads an empty descriptor for every object but GONE (missing) and DENIED (access refused); records adds."""
    added = []

    def __init__(self, samdb):
        pass

    def read_sd_on_dn(self, dn, controls=None):
        if dn == GONE:
            raise LdbError(32, f"No such Base DN: {dn}")
        if dn.startswith("CN=denied"):
            raise LdbError(50, "insufficient access")
        return Sd()

    def dacl_add_ace(self, dn, ace):
        SDUtils.added.append(dn)


security = types.SimpleNamespace(
    dom_sid=lambda s: s, SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT=5, SEC_ACE_TYPE_ACCESS_DENIED_OBJECT=6,
    descriptor=types.SimpleNamespace(from_sddl=lambda text, sid: types.SimpleNamespace(
        dacl=types.SimpleNamespace(aces=[Ace(text)]))))
sys.modules["ldb"] = types.SimpleNamespace(LdbError=LdbError, ERR_NO_SUCH_OBJECT=32)
sys.modules["samba"] = types.SimpleNamespace()
sys.modules["samba.dcerpc"] = types.SimpleNamespace(security=security)
sys.modules["samba.sd_utils"] = types.SimpleNamespace(SDUtils=SDUtils)
import acl_entries as m  # noqa: E402

FAILED = 0
SAMDB = types.SimpleNamespace(get_domain_sid=lambda: "S-1-5-21-1")
ACE = "(D;;WP;;;S-1-5-21-1-1100)"


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))


def error_of(call):
    try:
        call()
    except LdbError as e:
        return e.args[0]
    return None


SDUtils.added = []
done = m.ensure_aces(SAMDB, [(GONE, ACE), ("CN=bob,OU=people,DC=ad,DC=test", ACE)], gone_ok=True)
check("gone_ok: the account deleted since its search is skipped, the others still get their entry",
      SDUtils.added == ["CN=bob,OU=people,DC=ad,DC=test"] and len(done) == 1, (SDUtils.added, done))
check("without gone_ok (fabric's folders): a missing object is an error, as before",
      error_of(lambda: m.ensure_aces(SAMDB, [(GONE, ACE)])) == 32)
check("gone_ok never hides another refusal (access refused stands)",
      error_of(lambda: m.ensure_aces(SAMDB, [("CN=denied,DC=ad,DC=test", ACE)], gone_ok=True)) == 50)
print(f"{'all passed' if not FAILED else f'{FAILED} failed'} ({FAILED} failures)")
sys.exit(1 if FAILED else 0)
