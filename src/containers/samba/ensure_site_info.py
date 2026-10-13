import ldb

from id_layout import MARK_START, check_block
import paths


def ensure_site_info(samdb, site, id_range):
    """Purpose: a site's uid/gid block on its OU (2.1.6.17, 2.1.6.46, manual 1.6.3.9, 1.6.3.17): `fabricIdRange`
             "first-last" and one mark per fixed range, `fabricIdMark` "<kind>=<next>" (class fabricIdLayout), each
             starting at its range's first number. The block is set once: a site never changes its block (ids
             already handed out stay valid), and the marks only move forward (alloc_id). `fabricIdNext`, an older
             block's one run, is no longer written (S11; the schema keeps the attribute: AD never removes one).
    Inputs:  samdb — SamDB; site — str; id_range — str "first-last" (the root's: posix_id_start, posix_id_block long;
             a site's: from its parent at its join).
    Returns: list of str, what was added or set.
    Fails:   ldb.LdbError from a change AD refuses; ValueError from check_block (not a site's block), also for the
             block the OU already holds.
    Feeds:   converge."""
    check_block(id_range)
    dn = paths.site_dn(samdb, site)
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                        attrs=["objectClass", "fabricIdRange", "fabricIdMark"])[0]
    classes = [str(c) for c in have["objectClass"]]
    changes, done = {}, []
    if "fabricSiteInfo" not in classes:
        # the class first, on its own: AD checks a change's attributes against the classes the entry already has
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": "fabricSiteInfo"}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: objectClass fabricSiteInfo added")
    if "fabricIdRange" not in have:
        changes["fabricIdRange"] = id_range
    if changes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, **changes}, ldb.FLAG_MOD_REPLACE))
    done += [f"site {site}: {k} set" for k in sorted(changes)]
    held = str(have["fabricIdRange"][0]) if "fabricIdRange" in have else id_range
    lo, _ = check_block(held)
    if "fabricIdLayout" not in classes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": "fabricIdLayout"}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: objectClass fabricIdLayout added")
    kinds = {str(m).split("=", 1)[0] for m in have.get("fabricIdMark", [])}
    missing = [f"{kind}={lo + off}" for kind, off in MARK_START.items() if kind not in kinds]
    if missing:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "fabricIdMark": missing}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: id ranges' marks set ({', '.join(m.split('=')[0] for m in missing)})")
    return done
