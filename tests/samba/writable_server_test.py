"""The one choice of the DC a write to the domain goes to (decisions 2.1.6.52, 2.1.10.23; manual 1.6.11.13,
1.10.4.24.2): this site's own, or a read-only DC's writable partner, refused with none known; and the three places
that take it (the DHCP options' edits, the host's account, its undo) answering as they did before. Pure logic.
    python3 tests/samba/writable_server_test.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
import fabriclib.samba.writable_server as ws  # noqa: E402
from fabriclib.samba.writable_server import writable_server  # noqa: E402

UP = set()                       # the DCs that answer in this test; every other "does not answer"
ASKED = []


def _answers(server):
    ASKED.append(server)
    return server in UP


ws._answers = _answers
UP.update({"10.0.9.5"})

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def refused(v, to="write it at"):
    try:
        return writable_server(v, to), None
    except ValidationError as e:
        return None, str(e)


# the unit's cases
check("a writable DC's site writes at its own DC", refused({"ad_dc_type": "dc"}) == (None, None))
check("no DC type set is this site's own DC", refused({}) == (None, None))
check("a writable DC's site ignores ad_join_server (its own DC is writable)",
      refused({"ad_dc_type": "dc", "ad_join_server": "10.0.9.5"}) == (None, None))
check("a read-only DC's site writes at ad_join_server",
      refused({"ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"}) == ("10.0.9.5", None))
check("ad_join_server is trimmed", refused({"ad_dc_type": "rodc", "ad_join_server": " 10.0.9.5 "}) == ("10.0.9.5", None))
for blank in ("", "   ", None):
    server, why = refused({"ad_dc_type": "rodc", "ad_join_server": blank}, "make the host's account at")
    check(f"a read-only DC's site with ad_join_server={blank!r} is refused, naming the setting and the write",
          server is None and why == "this site's domain controller is read-only and no writable domain controller is "
          "known (ad_writable_servers, ad_join_server) to make the host's account at", why)
server, why = refused({"ad_dc_type": "rodc"})
check("a read-only DC's site with no ad_join_server at all is refused", server is None and "read-only" in (why or ""))

# the list of writable DCs, tried in order (2.1.6.57)
# covers: setting:ad_writable_servers +
UP.clear()
UP.update({"dc-b.ad.test"})
ws._seen.clear()
ASKED.clear()
rv = {"ad_dc_type": "rodc", "ad_join_server": "10.0.9.5", "ad_writable_servers": ["dc-a.ad.test", "dc-b.ad.test"]}
check("the list falls through to the second DC when the first does not answer",
      refused(rv, "write it at") == ("dc-b.ad.test", None) and ASKED == ["dc-a.ad.test", "dc-b.ad.test"], ASKED)
ASKED.clear()
check("an answer is remembered briefly: a second write asks nothing", refused(rv) == ("dc-b.ad.test", None)
      and ASKED == [], ASKED)
ASKED.clear()
check("...and asked again once the cache is old", writable_server(rv, "x", now=ws.time.time() + ws.CACHE_SECONDS + 5)
      == "dc-b.ad.test" and ASKED == ["dc-a.ad.test", "dc-b.ad.test"], ASKED)
UP.update({"dc-a.ad.test"})
ws._seen.clear()
check("the first that answers wins (the list's order)", refused(rv) == ("dc-a.ad.test", None))
check("the list replaces ad_join_server (never tried when the list is set)", "10.0.9.5" not in ASKED, ASKED)
UP.clear()
ws._seen.clear()
server, why = refused(rv, "make this change (create person) at")
check("negative: every DC down: refused, naming each DC tried and why, nothing chosen",
      server is None and "dc-a.ad.test: did not answer; dc-b.ad.test: did not answer" in why
      and "nothing was changed" in why and "create person" in why, why)
ws._seen.clear()
server, why = refused({"ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"})
check("negative: the one default DC down: refused, naming it", server is None and "10.0.9.5: did not answer" in why, why)
ws._seen.clear()
UP.update({"10.0.9.5"})
check("an empty list means [ad_join_server]", refused({"ad_dc_type": "rodc", "ad_join_server": "10.0.9.5",
                                                       "ad_writable_servers": []}) == ("10.0.9.5", None))
check("repeats are tried once", ws._candidates({"ad_writable_servers": ["a", " a ", "b"]}) == ["a", "b"])
check("a writable DC's site ignores the list", refused({"ad_dc_type": "dc", "ad_writable_servers": ["dc-a"]})
      == (None, None))

# the setting, checked at apply (samba/check_writable_servers)
from fabriclib.samba.check_writable_servers import check_writable_servers  # noqa: E402

check("the setting: names and addresses accepted, trimmed",
      check_writable_servers([" dc-a.ad.test ", "10.0.9.5", "fd00::5"]) == ["dc-a.ad.test", "10.0.9.5", "fd00::5"])
check("the setting: null and empty are []", check_writable_servers(None) == [] and check_writable_servers([]) == [])
# covers: setting:ad_writable_servers -
for bad, word in (("dc-a", "a list"), ([1], "name or an IP"), (["dc a"], "name or an IP"), (["-x.ad"], "name or an IP"),
                  (["a", "a"], "twice"), ([f"dc{i}" for i in range(9)], "at most 8"), ([""], "name or an IP")):
    try:
        check_writable_servers(bad)
        why = ""
    except ValidationError as e:
        why = str(e)
    check(f"negative: the setting {bad!r} refused ({word})", word in why and "ad_writable_servers" in why, why)

UP.update({"10.0.9.5"})
ws._seen.clear()
# the host's account (setup/common/host_identity): unchanged answers
from fabriclib.setup.common.host_identity import host_identity  # noqa: E402

mv = {"hostname": "fab1", "dc_name": "dc-fab1", "ad_domain": "ad.test"}
ident = host_identity(mv)
check("host_identity: a writable DC's site has no write_server", ident["write_server"] is None and not ident["refused"],
      ident)
ident = host_identity({**mv, "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"})
check("host_identity: a read-only DC's site writes at its partner",
      ident["write_server"] == "10.0.9.5" and not ident["refused"], ident)
ident = host_identity({**mv, "ad_dc_type": "rodc", "ad_join_server": ""})
check("host_identity: a read-only DC's site with no partner is refused with the old message",
      ident["write_server"] is None and ident["refused"] == "this site's domain controller is read-only and no writable "
      "domain controller is known (ad_writable_servers, ad_join_server) to make the host's account at", ident)
ident = host_identity({**mv, "dc_name": "fab1", "ad_dc_type": "rodc", "ad_join_server": ""})
check("host_identity: the DC's name taking the host's is still said first",
      "domain controller has this host's name" in ident["refused"], ident)

# the undo (undo/remove_host_account): the partner reaches remove_machine; with none, nothing is tried
import fabriclib.undo.remove_host_account as m_undo  # noqa: E402

calls = []
m_undo.remove_machine = lambda v, actor, name, source, secrets, server: calls.append(server)
d = tempfile.mkdtemp(prefix="fabric-writable-server-")
record = os.path.join(d, m_undo.RECORD)


def undo(v):
    with open(record, "w") as f:
        json.dump({"account": "FAB1"}, f)
    calls.clear()
    return m_undo.remove_host_account(d, v, lambda: {})


done = undo({"ad_dc_type": "dc"})
check("undo: a writable DC's site removes at its own DC", calls == [None] and "removed" in done[0], (calls, done))
done = undo({"ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"})
check("undo: a read-only DC's site removes at its partner", calls == ["10.0.9.5"] and "removed" in done[0],
      (calls, done))
done = undo({"ad_dc_type": "rodc", "ad_join_server": ""})
check("undo: a read-only DC's site with no partner says NOT removed and why, trying nothing",
      calls == [] and "NOT removed" in done[0] and "ad_join_server" in done[0], (calls, done))

# the DHCP options' edits (ipam/common/edit_options): the partner reaches write_plan; with none, nothing is written
import fabriclib.ipam.common.edit_options as m_edit  # noqa: E402

writes = []
m_edit.read_plan = lambda v, secrets, of=None, container="samba": {}
m_edit.site_plan = lambda plan, site: {}
m_edit.write_plan = lambda v, secrets, changes, container, server: writes.append(server) or []
m_edit.save_plan_cache = lambda plan: None
m_edit.write_audit = lambda *a: None
change = lambda plan: ([{"do": "set"}], "ok", "x", [])  # noqa: E731
writes.clear()
m_edit.edit_options({"site_name": "lan", "ad_dc_type": "rodc", "ad_join_server": "10.0.9.5"}, "t", "", "E", change,
                    secrets={})
check("edit_options: a read-only DC's site writes at its partner", writes == ["10.0.9.5"], writes)
writes.clear()
try:
    m_edit.edit_options({"site_name": "lan", "ad_dc_type": "rodc"}, "t", "", "E", change, secrets={})
    why = None
except ValidationError as e:
    why = str(e)
check("edit_options: a read-only DC's site with no partner is refused before anything is written",
      writes == [] and why and why.endswith("to write the change at: make it at the site above"), (writes, why))

print(f"\nwritable_server: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
