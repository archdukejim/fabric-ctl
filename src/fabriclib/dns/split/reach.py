ALL = "all"


def reach(record):
    """Purpose: whom a record answers (decision 2.1.4.17): its subnets, or every subnet.
    Inputs:  record — a stored record (dict).
    Returns: "all" when it has no `subnets` (every subnet: so are records from before 0.10.2), else the sorted list.
    Fails:   never.
    Feeds:   record_subnets (the CNAME clash), add_record, update_record, split_answers, default_records,
             reverse_zones, zone_detail."""
    subnets = record.get("subnets") if isinstance(record, dict) else None
    return ALL if subnets is None else sorted(str(s) for s in subnets)
