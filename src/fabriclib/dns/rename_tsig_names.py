def rename_tsig_names(data, old, new):
    """Purpose: A record of the site's zone renamed: every TSIG key of that zone granted the old name is granted the
             new one instead, in `records` and `records_with_aliases` (decision 2.1.4.12: a key's grant follows a
             rename). Today the only rename of a record is the host's own (4.2.4.3): its A record follows it.
    Inputs:  data — the vars (domain, tsig_keys), changed in place; old, new — the record's names (labels).
    Returns: list of the keys' names that followed.
    Fails:   never.
    Feeds:   breakglass/rename_host."""
    old, new = str(old or "").lower(), str(new or "").lower()
    followed = []
    if not old or not new or old == new:
        return followed
    for key in data.get("tsig_keys") or []:
        if (key.get("domain") or data.get("domain")) != data.get("domain"):
            continue
        moved = False
        for field in ("records", "records_with_aliases"):
            names = [str(r).lower() for r in key.get(field) or []]
            if old in names:
                key[field] = list(dict.fromkeys(new if n == old else n for n in names))
                moved = True
        if moved:
            followed.append(key.get("name"))
    return followed
