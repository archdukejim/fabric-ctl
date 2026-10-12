from fabriclib.common.errors import ValidationError
from fabriclib.samba.domain_sites import domain_sites
from fabriclib.samba.id_range import id_range

LAST_ID = 999_999_999       # site 999's block ends here: every id fabric gives stays below 1 000 000 000 (2.1.6.46)


def next_id_block(v, registry, container="samba", sites=None):
    """Purpose: the uid/gid block a new site gets at its join (2.1.6.17, 2.1.6.46, manual 1.6.3.9, 1.6.3.17): the next
             posix_id_block numbers after every block the domain holds (each site OU's, read from this site's DC: a
             parent that is not the root does not know the other branches' sites), this site's own and those its
             registry recorded. With blocks of a million from 1000000, site S's block starts at S × 1 000 000.
    Inputs:  v — this site's vars (its block: id_range; posix_id_block); registry — load_registry()'s dict;
             container — this site's DC; sites — domain_sites()'s list when the caller read it already.
    Returns: str "first-last".
    Fails:   ValueError for a malformed block; ValidationError when the DC cannot be read, or when the block would
             pass 999999999 (at most 999 sites; no setting raises it, manual 1.9.1.4).
    Feeds:   accept_join.
    Notes:   two parents handing out blocks while cut off from each other could pick the same one; AD replicates
             each site's block, so it is seen as soon as the link returns (manual 1.6.3.9)."""
    size = int(v.get("posix_id_block") or 1000000)
    held = domain_sites(container) if sites is None else sites
    blocks = [id_range(v)] + [s["id_range"] for s in held if s.get("id_range")]
    blocks += [str(s["id_range"]) for s in registry.get("sites", {}).values() if s.get("id_range")]
    first = max(int(b.split("-")[1]) for b in blocks) + 1
    if first + size - 1 > LAST_ID:
        raise ValidationError(f"no id block is left for another site: the domain's blocks end at {first - 1}, and "
                              f"fabric's ids stay below 1000000000 (at most 999 sites, manual 1.6.3.17)")
    return f"{first}-{first + size - 1}"
