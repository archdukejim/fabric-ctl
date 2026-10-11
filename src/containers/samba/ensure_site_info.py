import ldb

from id_layout import MARK_START, laid_out
import paths


def ensure_site_info(samdb, site, id_range):
    """Purpose: a site's uid/gid block on its OU (2.1.6.17, 2.1.6.46, manual 1.6.3.9, 1.6.3.17): `fabricIdRange`
             "first-last" and the high-water mark `fabricIdNext`, starting at the block's first number; a block laid
             out in fixed ranges also gets one mark per range, `fabricIdMark` "<kind>=<next>" (class fabricIdLayout),
             each starting at its range's first number. The block is set once: a site never changes its block (ids
             already handed out stay valid), and the marks only move forward (alloc_id).
    Inputs:  samdb — SamDB; site — str; id_range — str "first-last" (the root's: posix_id_start, posix_id_block long;
             a site's: from its parent at its join).
    Returns: list of str, what was added or set.
    Fails:   ldb.LdbError from a change AD refuses; ValueError for a malformed id_range.
    Feeds:   converge."""
    first, last = (int(x) for x in id_range.split("-"))
    if not 0 < first <= last:
        raise ValueError(f"id range {id_range!r}: first-last, both positive")
    dn = paths.site_dn(samdb, site)
    have = samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                        attrs=["objectClass", "fabricIdRange", "fabricIdNext", "fabricIdMark"])[0]
    classes = [str(c) for c in have["objectClass"]]
    changes, done = {}, []
    if "fabricSiteInfo" not in classes:
        # the class first, on its own: AD checks a change's attributes against the classes the entry already has
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": "fabricSiteInfo"}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: objectClass fabricSiteInfo added")
    if "fabricIdRange" not in have:
        changes["fabricIdRange"] = id_range
    if "fabricIdNext" not in have:
        changes["fabricIdNext"] = str(first)
    if changes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, **changes}, ldb.FLAG_MOD_REPLACE))
    done += [f"site {site}: {k} set" for k in sorted(changes)]
    held = str(have["fabricIdRange"][0]) if "fabricIdRange" in have else id_range
    lo, hi = (int(x) for x in held.split("-"))
    if not laid_out(lo, hi):                    # an older install's block: one run, no marks
        return done
    if "fabricIdLayout" not in classes:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "objectClass": "fabricIdLayout"}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: objectClass fabricIdLayout added")
    kinds = {str(m).split("=", 1)[0] for m in have.get("fabricIdMark", [])}
    missing = [f"{kind}={lo + off}" for kind, off in MARK_START.items() if kind not in kinds]
    if missing:
        samdb.modify(ldb.Message.from_dict(samdb, {"dn": dn, "fabricIdMark": missing}, ldb.FLAG_MOD_ADD))
        done.append(f"site {site}: id ranges' marks set ({', '.join(m.split('=')[0] for m in missing)})")
    return done
