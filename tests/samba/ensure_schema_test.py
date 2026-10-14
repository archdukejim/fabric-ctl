"""fabric's schema numbers each given once (manual 1.6.3.5: a schema OID is permanent, so a number two branches both
took would make two attributes or classes one): src/containers/samba/ensure_schema.SETS, every attribute number and
every class number used once in its set, every name once, every OID once, each class naming only attributes that
exist, and no live entry on a number in ensure_schema.RETIRED. Settled 2026-10-13 after 0.8.0's scan policy and 0.9's
SSH host certificates both took 35, 36 and class 13 (2.1.7.13, revised); 2.1.10.30 then dropped the scan policy, so
35, 36 and class 13 are retired and never reused. Pure logic, no container: Samba's ldb and the DC's open_samdb are
stand-ins.
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
from ensure_schema import RETIRED, SETS  # noqa: E402

PASS = FAIL = 0
# attributes the classes may name that are not fabric's own: AD's
BUILT_IN = {"cn", "description"}


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {str(detail)[:400]}")


def problems(sets, retired):
    """Every number, name or OID used more than once, every class naming an attribute nobody defines, and every live
    entry on a retired number."""
    out, oids, attrs = [], collections.Counter(), set(BUILT_IN)
    for key, (attr_arc, class_arc, attributes, classes) in sets.items():
        for kind, rows, arc in (("attribute", attributes, attr_arc), ("class", classes, class_arc)):
            for what, values in (("number", [r[1] for r in rows]), ("name", [r[0] for r in rows])):
                out += [f"{key}: {kind} {what} {v} used {n} times"
                        for v, n in collections.Counter(values).items() if n > 1]
            oids.update(f"{arc}.{r[1]}" for r in rows)
            gone = retired.get(key, {}).get("classes" if kind == "class" else "attributes", set())
            out += [f"{key}: {kind} {r[0]} takes retired number {r[1]}" for r in rows if r[1] in gone]
        attrs.update(r[0] for r in attributes)
    out += [f"OID {o} used {n} times" for o, n in oids.items() if n > 1]
    for key, (_, _, _, classes) in sets.items():
        for c in classes:
            out += [f"{key}: class {c[0]} names {a}, which no set defines"
                    for a in list(c[3]) + list(c[4]) if a not in attrs]
    return out


def main():
    found = problems(SETS, RETIRED)
    check("every attribute and class number, name and OID used once; classes name only attributes that exist; "
          "no live entry on a retired number", not found, found)

    numbers = {r[0]: r[1] for _, _, attributes, classes in SETS.values() for r in attributes + classes}
    check("2.1.10.28's scan policy is retired: attributes 35, 36 and class 13 in RETIRED, its names gone",
          RETIRED.get("fabric") == {"attributes": {35, 36}, "classes": {13}}
          and not {"fabricScanPolicy", "fabricScanEnforced", "fabricScanPolicySet"} & set(numbers), RETIRED)
    scans = {"fabricLocalScan": 39, "fabricLocalScanBy": 40, "fabricScanRequestedBy": 41, "fabricScanActor": 42,
             "fabricScanState": 43, "fabricScanResult": 44, "fabricScanDoneAt": 45,
             "fabricLocalScanSet": 15, "fabricScanRequest": 16}
    check("scans from the top down take attributes 39-45 and classes 15, 16 (2.1.10.30)",
          {k: numbers.get(k) for k in scans} == scans, {k: numbers.get(k) for k in scans})
    # 37, 38 and class 14 are the SSH host schema's (0.9, 2.1.7.13 revised): on a branch that has it, those names;
    # on one that has not, nobody else's
    ssh = {"fabricSshHostKey": 37, "fabricSshHostCert": 38, "fabricSshHost": 14}
    fabric_attrs, fabric_classes = SETS["fabric"][2], SETS["fabric"][3]
    held = {r[0]: r[1] for r in fabric_attrs if r[1] in (37, 38)}
    held.update({r[0]: r[1] for r in fabric_classes if r[1] == 14})
    check("attributes 37, 38 and class 14 are the SSH host schema's, or nobody's (2.1.7.13, revised 2026-10-13)",
          all(ssh.get(name) == n for name, n in held.items()), held)

    # negatives: the check itself finds each kind of clash (so a later merge that reuses a number fails here)
    arc_a, arc_c, attributes, classes = SETS["fabric"]
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes + [("fabricClash", attributes[-1][1], "x", True)], classes))
    check("negative: an attribute number used twice is found, naming it",
          any(f"attribute number {attributes[-1][1]} used 2 times" in p for p in problems(bad, RETIRED)),
          problems(bad, RETIRED))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, classes + [("fabricClashSet", classes[-1][1], 3, [], [])]))
    check("negative: a class number used twice is found, naming it",
          any(f"class number {classes[-1][1]} used 2 times" in p for p in problems(bad, RETIRED)),
          problems(bad, RETIRED))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes + [(attributes[0][0], 999, "x", True)], classes))
    check("negative: an attribute name used twice is found",
          any("attribute name" in p for p in problems(bad, RETIRED)), problems(bad, RETIRED))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, classes + [("fabricOdd", 999, 3, [], ["fabricNoSuch"])]))
    check("negative: a class naming an attribute nobody defines is found",
          any("fabricNoSuch" in p for p in problems(bad, RETIRED)), problems(bad, RETIRED))
    bad = dict(SETS, copy=(arc_a, arc_c, [("fabricOther", attributes[0][1], "x", True)], []))
    check("negative: one OID in two sets (the same arc) is found",
          any(p.startswith("OID ") for p in problems(bad, RETIRED)), problems(bad, RETIRED))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes + [("fabricReuse", 35, "x", True)], classes))
    check("negative: a live attribute on retired number 35 is found, naming it",
          any("fabricReuse takes retired number 35" in p for p in problems(bad, RETIRED)), problems(bad, RETIRED))
    bad = dict(SETS, fabric=(arc_a, arc_c, attributes, classes + [("fabricReuseSet", 13, 3, [], [])]))
    check("negative: a live class on retired number 13 is found, naming it",
          any("fabricReuseSet takes retired number 13" in p for p in problems(bad, RETIRED)),
          problems(bad, RETIRED))


if __name__ == "__main__":
    try:
        main()
    except Exception:  # a crash is a failure, and the summary still prints
        FAIL += 1
        traceback.print_exc()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
