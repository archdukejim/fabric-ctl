def tsig_key_mode(key, choices):
    """Purpose: A TSIG key's mode as a person sees it (decision 2.1.4.12): "acme" when it holds no more than ACME
             (DNS-01) mode gives (TXT at the challenge names of records of its zone, and records with their
             aliases), else "custom". Nothing stores the mode: a key made by hand, or from before 0.10.0, that uses
             more shows as Custom.
    Inputs:  key — a normalized tsig_keys entry; choices — key_record_choices() for its zone ([] when the zone is
             gone).
    Returns: "acme" or "custom".
    Fails:   never.
    Feeds:   list_tsig_keys, edit_tsig_names, drop_removed_names."""
    names = {c["name"] for c in choices}
    addresses = {c["name"] for c in choices if c["address"]}
    records = [str(r).lower() for r in key.get("records") or []]
    with_aliases = [str(r).lower() for r in key.get("records_with_aliases") or []]
    if not records and not with_aliases:
        return "custom"
    if key.get("primary") or key.get("any_name"):
        return "custom"
    if [str(t).upper() for t in key.get("record_types") or ["TXT"]] != ["TXT"]:
        return "custom"
    if any(r not in names for r in records) or any(r not in addresses for r in with_aliases):
        return "custom"
    return "acme"
