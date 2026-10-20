import ldb

from id_layout import MARK_START, check_block, dc_range
import paths

# the auxiliary classes a DC's record carries: its range (fabricIdRange), the ranges' marks (fabricIdMark), its site
CLASSES = ("fabricSiteInfo", "fabricIdLayout", "fabricDcInfo")


def ensure_dc_record(samdb, dc, site):
    """Purpose: a DC's record in fabric's state (2.1.6.79, 2.1.6.63, 2.1.6.85; manual 1.6.13.2): `CN=<dc>,CN=dcs,
             CN=fabric,CN=System`, holding the id range its number gives it (`fabricIdRange`), one mark per fixed range
             (`fabricIdMark` "<kind>=<next>", each starting at its range's first number) and its site (`fabricSite`).
             The range and the site are set once: a DC keeps its number, and the marks only move forward (alloc_id).
             Made by the DC's own convergence, or by the writable DC that prepares its join (a read-only DC cannot
             write it, 2.1.6.85).
    Inputs:  samdb — SamDB (as the system); dc — the DC's name (dc-NNNN); site — its site's name.
    Returns: list of str, what was added or set.
    Fails:   ValueError from dc_range (not a numbered DC name), or for a record whose range is not the number's;
             ldb.LdbError from a change AD refuses (CN=dcs missing: ensure_layout makes it first).
    Feeds:   converge."""
    want = dc_range(dc)
    dn = paths.dc_record_dn(samdb, dc)
    done = []
    try:
        samdb.add({"dn": dn, "objectClass": "container"})
        done.append(f"DC record {dc} created")
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
            raise
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                        attrs=["objectClass", "fabricIdRange", "fabricIdMark", "fabricSite"])[0]
    classes = [str(c) for c in have["objectClass"]]
    for cls in CLASSES:          # each class first, on its own: AD checks a change against the classes held already
        if cls not in classes:
            samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": cls}, ldb.FLAG_MOD_ADD))
    changes = {}
    if "fabricIdRange" not in have:
        changes["fabricIdRange"] = want
    elif str(have["fabricIdRange"][0]) != want:
        raise ValueError(f"the record of {dc} holds the range {have['fabricIdRange'][0]}, not {want}: a DC's range "
                         "is its number's (2.1.6.63)")
    if "fabricSite" not in have:
        changes["fabricSite"] = site
    if changes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, **changes}, ldb.FLAG_MOD_REPLACE))
        done += [f"DC record {dc}: {k} set" for k in sorted(changes)]
    lo, _ = check_block(want)
    kinds = {str(m).split("=", 1)[0] for m in have.get("fabricIdMark", [])}
    missing = [f"{kind}={lo + off}" for kind, off in MARK_START.items() if kind not in kinds]
    if missing:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "fabricIdMark": missing}, ldb.FLAG_MOD_ADD))
        done.append(f"DC record {dc}: id ranges' marks set ({', '.join(m.split('=')[0] for m in missing)})")
    return done
