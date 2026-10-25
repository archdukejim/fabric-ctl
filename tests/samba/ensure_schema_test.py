"""fabric's schema numbers each given once (manual 1.6.3.5; 2.1.8.30, and 2.1.10.33 on dev/0.9.0): a schema OID is
permanent, so src/containers/samba/ensure_schema.SETS gives every attribute and class number once in its set, every
name once, every OID once, each class naming only attributes that exist, no live entry on a RETIRED or RESERVED
number; 0.8.0's numbers as 0.8.0 ships them (fabricDcInfo class 7), 0.9.0's site record (class 18) brought forward
exactly with the attributes it names, the site selector's own (46, 47, class 19); and schema_problems finds a domain
whose schema disagrees (a lab domain that ran a pre-release VLAN record as class 7).
Pure logic, no container: Samba's ldb and the DC's open_samdb are stand-ins.
    python3 tests/samba/ensure_schema_test.py"""
import collections
import os
import sys
import traceback
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src", "containers", "samba"))
sys.modules.setdefault("ldb", types.ModuleType("ldb"))
_samdb = types.ModuleType("open_samdb")
_samdb.open_samdb = None
sys.modules.setdefault("open_samdb", _samdb)
from ensure_schema import FABRIC_ARC, RESERVED, RETIRED, SETS, schema_problems, wanted_oids  # noqa: E402

PASS = FAIL = 0
# attributes the classes may name that are not fabric's own: AD's
BUILT_IN = {"cn", "description"}


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


def problems(sets, held):
    """Purpose: every number, name or OID used more than once, every class naming an attribute nobody defines, and
             every live entry on a number held (retired or reserved).
    Inputs:  sets — SETS' shape; held — {set: {"attributes": {n}, "classes": {n}}}, RETIRED and RESERVED merged.
    Returns: list of str.
    Fails:   never.
    Feeds:   main."""
    out, oids, attrs = [], collections.Counter(), set(BUILT_IN)
    for key, (attr_arc, class_arc, attributes, classes) in sets.items():
        for kind, rows, arc in (("attribute", attributes, attr_arc), ("class", classes, class_arc)):
            for what, values in (("number", [r[1] for r in rows]), ("name", [r[0] for r in rows])):
                out += [f"{key}: {kind} {what} {v} used {n} times"
                        for v, n in collections.Counter(values).items() if n > 1]
            oids.update(f"{arc}.{r[1]}" for r in rows)
            gone = held.get(key, {}).get("classes" if kind == "class" else "attributes", set())
            out += [f"{key}: {kind} {r[0]} takes held number {r[1]}" for r in rows if r[1] in gone]
        attrs.update(r[0] for r in attributes)
    out += [f"OID {o} used {n} times" for o, n in oids.items() if n > 1]
    for key, (_, _, _, classes) in sets.items():
        for c in classes:
            out += [f"{key}: class {c[0]} names {a}, which no set defines"
                    for a in list(c[3]) + list(c[4]) if a not in attrs]
    return out


def main():
    """Purpose: the checks, positive and negative.
    Inputs:  none.
    Returns: None.
    Fails:   never (a crash is counted by the caller).
    Feeds:   this script."""
    held = {"fabric": {"attributes": RETIRED["fabric"]["attributes"] | RESERVED["fabric"]["attributes"],
                       "classes": RETIRED["fabric"]["classes"] | RESERVED["fabric"]["classes"]}}
    found = problems(SETS, held)
    check("every number, name and OID used once; classes name only attributes that exist; nothing on a retired or "
          "reserved number", not found, found)

    attrs = {r[0]: r[1] for r in SETS["fabric"][2]}
    classes = {r[0]: r[1] for r in SETS["fabric"][3]}
    check("0.8.0's schema as it ships: attributes 1-14, classes 1-7, fabricDcInfo 7",
          {n for n in attrs.values() if n <= 14} == set(range(1, 15)) and classes.get("fabricDcInfo") == 7
          and {n for n in classes.values() if n <= 7} == set(range(1, 8)), (attrs, classes))
    check("0.9.0's site record brought forward under its numbers: class 18 and the attributes it names, 21, 31, 33, "
          "34; nothing else of 0.9.0's 8-17 or 15-45", classes.get("fabricSiteRecord") == 18
          and {n for n in classes.values() if 7 < n < 19} == {18}
          and {k: attrs.get(k) for k in ("fabricDhcpOption", "fabricBlock", "fabricDhcpOptionDef", "fabricDhcpClass")}
          == {"fabricDhcpOption": 21, "fabricBlock": 31, "fabricDhcpOptionDef": 33, "fabricDhcpClass": 34}
          and {n for n in attrs.values() if 14 < n < 46} == {21, 31, 33, 34}, (sorted(attrs.values()), classes))
    check("the site selector's own: fabricParentSite 46, fabricConsoleUrl 47, auxiliary class fabricSiteTree 19",
          attrs.get("fabricParentSite") == 46 and attrs.get("fabricConsoleUrl") == 47
          and classes.get("fabricSiteTree") == 19 and {n for n in attrs.values() if n > 45} == {46, 47}
          and {n for n in classes.values() if n > 18} == {19}, (attrs, classes))
    tree = next(c for c in SETS["fabric"][3] if c[0] == "fabricSiteTree")
    check("...auxiliary, may hold the two only", tree[2] == 3 and tree[3] == []
          and tree[4] == ["fabricParentSite", "fabricConsoleUrl"], tree)
    check("retired: attributes 35, 36, 39, 40 and classes 11, 13, 15; reserved for 0.10.0: 37, 38 and class 14",
          RETIRED["fabric"] == {"attributes": {35, 36, 39, 40}, "classes": {11, 13, 15}}
          and RESERVED["fabric"] == {"attributes": {37, 38}, "classes": {14}}, (RETIRED, RESERVED))
    gone = {"fabricAddressBlock", "fabricScanPolicySet", "fabricLocalScanSet", "fabricScanPolicy",
            "fabricScanEnforced", "fabricLocalScan", "fabricLocalScanBy"}
    check("no dropped name is live", not gone & (set(attrs) | set(classes)), gone & (set(attrs) | set(classes)))
    site = next(c for c in SETS["fabric"][3] if c[0] == "fabricSiteRecord")
    check("the site's record is structural, in a container, holding the number and the option lists",
          site[2] == 1 and site[5] == ["container"]
          and {"fabricBlock", "fabricDhcpOption", "fabricDhcpOptionDef", "fabricDhcpClass"} <= set(site[4]), site)

    # schema_problems: a schema that agrees, and each kind of disagreement
    agree = wanted_oids()
    check("a schema holding exactly fabric's numbers agrees", schema_problems(agree) == [], schema_problems(agree))
    check("a schema of 0.7's alone agrees (the rest is added)",
          schema_problems({n: o for n, o in agree.items() if n in ("fabricDcInfo", "fabricSite", "fabricIdMark")})
          == [])
    check("a later release's name on a number fabric does not give is no disagreement",
          schema_problems(dict(agree, fabricSshHost=f"{FABRIC_ARC}.2.14")) == [])
    lab = dict(agree)
    del lab["fabricDcInfo"]
    lab["fabricVlanRecord"] = f"{FABRIC_ARC}.2.7"
    found = schema_problems(lab)
    check("negative: a pre-release VLAN record on class 7 is refused, naming it and fabricDcInfo",
          any("is fabricVlanRecord here, fabricDcInfo in fabric" in p for p in found), found)
    other = dict(agree)
    del other["fabricSiteTree"]
    other["fabricOldTree"] = f"{FABRIC_ARC}.2.19"
    found = schema_problems(other)
    check("negative: one of fabric's numbers under another name is refused, naming both",
          any("fabricOldTree here, fabricSiteTree in fabric" in p for p in found), found)
    moved = dict(agree, fabricSiteRecord=f"{FABRIC_ARC}.2.17")
    check("negative: the site record under another number than 0.9.0's is refused",
          any(p.startswith("fabricSiteRecord is ") for p in schema_problems(moved)), schema_problems(moved))

    # negatives: the uniqueness check finds each kind of clash (so a later merge that reuses a number fails here)
    arc_a, arc_c, attributes, klasses = SETS["fabric"]
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes + [("fabricClash", attributes[-1][1], "x", True)], klasses))
    check("negative: an attribute number used twice is found",
          any(f"attribute number {attributes[-1][1]} used 2 times" in p for p in problems(bad, held)))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, klasses + [("fabricClashSet", klasses[-1][1], 3, [], [])]))
    check("negative: a class number used twice is found",
          any(f"class number {klasses[-1][1]} used 2 times" in p for p in problems(bad, held)))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, klasses + [("fabricOdd", 999, 3, [], ["fabricNoSuch"])]))
    check("negative: a class naming an attribute nobody defines is found",
          any("fabricNoSuch" in p for p in problems(bad, held)))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes + [("fabricReuse", 39, "x", True)], klasses))
    check("negative: a live attribute on retired number 39 is found",
          any("fabricReuse takes held number 39" in p for p in problems(bad, held)))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, klasses + [("fabricTaken", 14, 3, [], [])]))
    check("negative: a live class on reserved number 14 is found",
          any("fabricTaken takes held number 14" in p for p in problems(bad, held)))


if __name__ == "__main__":
    try:
        main()
    except Exception:  # a crash is a failure, and the summary still prints
        FAIL += 1
        traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
