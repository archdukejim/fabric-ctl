"""The grants' networks rights, their pure parts (manual 1.6.13.12; 2.1.10.36): check_grant taking networks rights
(plan, options, scan) with the sites they hold at (`all` alone, or sites of the domain), a grant of networks rights
alone needing no where, and refusing sites without networks rights, networks rights without sites, an unknown right
or site and a restricting grant with them; authorize_action's networks:<right> at a site: the tiers everywhere, a
delegated person only through an allowing grant at that site or at all, the domain's own (`all`) only through a
grant at all, a restricting grant never; ship_grants making network-plan once, on a fresh install and on an 0.8.0
domain (already shipped), and never again once removed; the template site-networks. Pure logic, no container: the
directory is a stand-in; the real DC's run is tests/samba/grants.py.
    python3 tests/samba/grant_networks_test.py"""
import os
import sys
import traceback
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))
ldb = types.ModuleType("ldb")
ldb.LdbError = type("LdbError", (Exception,), {})
ldb.ERR_NO_SUCH_OBJECT, ldb.SCOPE_BASE, ldb.SCOPE_ONELEVEL, ldb.SCOPE_SUBTREE = 32, 0, 1, 2
ldb.binary_encode = str
sys.modules["ldb"] = ldb
import authorize_action as aa  # noqa: E402
import check_grant as cg  # noqa: E402
import ship_grants as sg  # noqa: E402
from grant_names import SHIPPED, TEMPLATES  # noqa: E402

PASS = FAIL = 0
GROUPS = {"network-admins", "site-lan", "site-branch", "machines-network", "server-admins"}


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
        if words in str(e):
            return True
        print(f"    refused, but not for {words!r}: {e}")
    return False


class _Samdb:
    """A stand-in SamDB: its domain's SID, and nothing searched."""

    def get_domain_sid(self):
        return "S-1-5-21-1"

    def search(self, **kw):
        raise AssertionError("AD was searched")


def _find_group(samdb, name):
    """Purpose: the stand-in directory's groups.
    Inputs:  samdb — unused; name — str.
    Returns: (dn, sid) or None.
    Fails:   never.
    Feeds:   check_grant (patched)."""
    return (f"cn={name},ou=groups", f"S-1-5-21-1-{2000 + len(name)}") if name.lower() in GROUPS else None


class _Who:
    """A stand-in account found by name."""

    def __init__(self, name):
        self.dn = f"CN={name},OU=people,DC=ad,DC=test"


def _dn(name):
    """Purpose: a stand-in person's DN, lower case as authorize_action compares them.
    Inputs:  name — a user name.
    Returns: str.
    Fails:   never.
    Feeds:   _patch_authorize."""
    return f"cn={name},ou=people,dc=ad,dc=test"


def _patch_authorize(grants, members):
    """Purpose: authorize_action reading a stand-in directory: no tiers but the Directory Administrator dora, the
             grants given, and each grant's who reached as `members` says.
    Inputs:  grants — list of stored grants; members — {grant name: [user names in its who]}.
    Returns: None.
    Fails:   never.
    Feeds:   main."""
    aa.tiers = lambda samdb: {"ad_top": set(), "fabric_accounts": set(), "directory_admins": {_dn("dora")},
                              "dc_hosts": set()}
    aa.excluded = lambda samdb: {}
    aa.read_grants = lambda samdb: [{**cg.FIELDS, **g} for g in grants]
    aa.reach = lambda samdb, g, out, cache: {"who": {_dn(n): n for n in members.get(g["name"], [])},
                                             "where_people": {}, "where_computers": {}}
    aa._account = lambda samdb, name, computer=False: _Who(name)


def _check_grants(s):
    """Purpose: check_grant's networks rights and sites, positive and negative.
    Inputs:  s — the stand-in SamDB.
    Returns: None.
    Fails:   never.
    Feeds:   main."""
    cg.find_group = _find_group
    cg._everyone = lambda samdb, name: False
    g = cg.check_grant(s, {"name": "lan-plan", "who": ["network-admins"], "networks": ["plan", "scan"],
                           "sites": ["lan"]})
    check("networks rights alone, at a site: no where needed", g["networks"] == ["plan", "scan"]
          and g["sites"] == ["lan"] and g["where"] == [], g)
    g = cg.check_grant(s, {"name": "all-plan", "who": ["network-admins"], "networks": ["options"], "sites": ["all"]})
    check("networks rights at all", g["sites"] == ["all"], g)
    g = cg.check_grant(s, {"name": "mixed", "who": ["network-admins"], "where": ["machines-network"],
                           "signin": ["remote"], "networks": ["plan"], "sites": ["lan", "branch"]})
    check("networks rights beside sign-in rights, with a where", g["sites"] == ["lan", "branch"], g)
    g = cg.check_grant(s, {"name": "old", "who": ["server-admins"], "where": ["machines-network"],
                           "signin": ["keyboard"]})
    check("an 0.8.0 grant: no networks, no sites", g["networks"] == [] and g["sites"] == [], g)
    check("negative: a grant with sign-in rights still needs a where", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "signin": ["remote"],
                                   "networks": ["plan"], "sites": ["lan"]}), "where: at least one group"))
    check("negative: networks rights still need a who", refused(
        lambda: cg.check_grant(s, {"name": "bad", "networks": ["plan"], "sites": ["lan"]}), "who: at least one group"))
    check("negative: networks rights with no site", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "networks": ["plan"]}),
        "names at least one site"))
    check("negative: sites with no networks rights", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "where": ["machines-network"],
                                   "signin": ["remote"], "sites": ["lan"]}), "only for networks rights"))
    check("negative: all beside a site", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "networks": ["plan"],
                                   "sites": ["all", "lan"]}), "all (every site) alone"))
    check("negative: a site the domain does not have", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "networks": ["plan"],
                                   "sites": ["nowhere"]}), "no site nowhere in the domain"))
    check("negative: an unknown networks right", refused(
        lambda: cg.check_grant(s, {"name": "bad", "who": ["network-admins"], "networks": ["local-scan"],
                                   "sites": ["lan"]}), "local-scan is not one of plan, options, scan"))
    check("negative: a restricting grant cannot narrow networks rights", refused(
        lambda: cg.check_grant(s, {"name": "bad", "kind": "restrict", "who": ["network-admins"],
                                   "where": ["machines-network"], "signin": ["remote"], "networks": ["plan"],
                                   "sites": ["lan"]}), "a restricting grant narrows sign-in"))


def _check_authorize(s):
    """Purpose: authorize_action's networks rights, positive and negative.
    Inputs:  s — the stand-in SamDB.
    Returns: None.
    Fails:   never.
    Feeds:   main."""
    grants = [{"name": "lan-plan", "who": ["network-admins"], "networks": ["plan"], "sites": ["lan"]},
              {"name": "all-options", "who": ["network-admins"], "networks": ["options"], "sites": ["all"]},
              {"name": "no-net", "kind": "restrict", "who": ["network-admins"], "where": ["machines-network"],
               "signin": ["remote"], "networks": ["scan"], "sites": ["all"]}]
    _patch_authorize(grants, {"lan-plan": ["nina"], "all-options": ["olga"], "no-net": ["nina", "olga", "rita"]})
    check("a delegated person with a grant at the site", aa.authorize_action(
        s, "nina", "networks:plan", {"site": "lan"}) == {"tier": "delegated", "by": "grant lan-plan"})
    check("a site's name matched without case", aa.authorize_action(
        s, "nina", "networks:plan", {"site": "LAN"})["by"] == "grant lan-plan")
    check("negative: the same person at another site", refused(
        lambda: aa.authorize_action(s, "nina", "networks:plan", {"site": "branch"}),
        "no grant gives you networks plan at branch"))
    check("negative: the same person with another right", refused(
        lambda: aa.authorize_action(s, "nina", "networks:options", {"site": "lan"}), "networks options at lan"))
    check("negative: a grant at one site does not reach the domain's own", refused(
        lambda: aa.authorize_action(s, "nina", "networks:plan", {"site": "all"}), "every site (the domain's own)"))
    check("a grant at all reaches every site and the domain's own",
          aa.authorize_action(s, "olga", "networks:options", {"site": "branch"})["by"] == "grant all-options"
          and aa.authorize_action(s, "olga", "networks:options", {"site": "all"})["by"] == "grant all-options")
    check("negative: a restricting grant gives no networks right", refused(
        lambda: aa.authorize_action(s, "rita", "networks:scan", {"site": "lan"}), "no grant gives you"))
    check("negative: a person in no grant", refused(
        lambda: aa.authorize_action(s, "pete", "networks:options", {"site": "lan"}), "no grant gives you"))
    check("a Directory Administrator holds every networks right everywhere", aa.authorize_action(
        s, "dora", "networks:scan", {"site": "all"}) == {"tier": "directory", "by": "tier"})
    check("root acts for the Enterprise Admin", aa.authorize_action(
        s, None, "networks:plan", {"site": "lan"}) == {"tier": "enterprise", "by": "tier"})
    check("negative: an unknown networks right", refused(
        lambda: aa.authorize_action(s, "dora", "networks:local-scan", {"site": "lan"}), "unknown action"))
    check("negative: no site named", refused(
        lambda: aa.authorize_action(s, "dora", "networks:plan", {}), "checked at a site, or at all"))


def _check_shipping(s):
    """Purpose: ship_grants' network-plan, made once on a fresh install and on an upgraded 0.8.0 domain.
    Inputs:  s — the stand-in SamDB.
    Returns: None.
    Fails:   never.
    Feeds:   main."""
    store, state = {}, {"next": 1, "sets": {}, "shipped": False, "shipped_networks": False}
    sg.read_state = lambda samdb: dict(state)
    sg.write_state = lambda samdb, st: state.update(st)
    sg.read_grant = lambda samdb, name: store.get(name)
    sg.write_grant = lambda samdb, grant: store.__setitem__(grant["name"], grant)
    sg.check_grant = lambda samdb, grant: {**cg.FIELDS, **grant}
    made = sg.ship_grants(s)
    plan = store.get("network-plan", {})
    check("a fresh install ships the 0.8.0 grants and network-plan", len(made) == len(SHIPPED) + 1
          and plan.get("who") == ["network-admins"] and plan.get("sites") == ["all"]
          and plan.get("networks") == ["plan", "options", "scan"] and state["shipped_networks"], made)
    check("negative: shipped once: nothing made again", sg.ship_grants(s) == [])
    store.clear()
    state.update({"shipped": True, "shipped_networks": False})
    check("an 0.8.0 domain upgraded gets network-plan alone",
          sg.ship_grants(s) == ["grant network-plan made (shipped)"] and list(store) == ["network-plan"])
    del store["network-plan"]
    check("negative: removed by an admin, it is not made again", sg.ship_grants(s) == [] and not store)
    check("the template site-networks: every networks right, no site",
          TEMPLATES["site-networks"]["networks"] == ["plan", "options", "scan"]
          and "sites" not in TEMPLATES["site-networks"])


def main():
    """Purpose: the checks, positive and negative.
    Inputs:  none.
    Returns: None.
    Fails:   never (a crash is counted by the caller).
    Feeds:   this script."""
    s = _Samdb()
    _check_grants(s)
    _check_authorize(s)
    _check_shipping(s)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # a crash is a failure, and the summary still prints
        FAIL += 1
        traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
