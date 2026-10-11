def id_range(v):
    """Purpose: this site's uid/gid block (2.1.6.17, 2.1.6.46, manual 1.6.3.9, 1.6.3.17) as "first-last": the root's
             starts at posix_id_start (1000000 for new installs: site 1's block; an install from before 0.7.0 keeps
             where its people's range started, 5001 by default, keep_old_install) and is posix_id_block numbers long
             (1000000; 100000 before 0.7.0). A site that joined gets its block from its parent (posix_id_range).
    Inputs:  v — rendered vars: posix_id_range (a joined site's), posix_id_start, posix_id_block.
    Returns: str "first-last".
    Fails:   ValueError for a start or size that is not a number.
    Feeds:   converge_domain; federation/next_id_block (this site's own block)."""
    if v.get("posix_id_range"):
        return str(v["posix_id_range"])
    first = int(v.get("posix_id_start") or 1000000)
    return f"{first}-{first + int(v.get('posix_id_block') or 1000000) - 1}"
