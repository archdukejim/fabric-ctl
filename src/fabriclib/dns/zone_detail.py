from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.format_value import format_value
from fabriclib.dns.ptr_for_ip import ptr_for_ip
from fabriclib.dns.sync_status import sync_status
from fabriclib.dns.zone_name import zone_name
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.reach import ALL, reach
from fabriclib.dns.split.record_subnets import default_reach
from fabriclib.ipam.common.plan_cache import load_plan_cache

# the stored field a record's one value is (its edit row, 2.1.4.15)
EDIT_VALUE = {"A": "ip", "AAAA": "ip", "CNAME": "canonical", "MX": "exchange", "TXT": "text", "SRV": "target"}


def zone_detail(key):
    """Purpose: One zone for the zone page: its records with display values, where each A/AAAA record's automatic PTR
             goes (or why there is none), and BIND's sync status.
    Inputs:  key — str zone key in `dns:`. Reads vars.yaml; runs sync_status (docker exec rndc).
    Returns: {"key", "name", "records": [{"type", "index", "name", "value", "fabric" ({"service", "setting"} for one
             of fabric's own names, 2.1.2.22, else None), "edit" ({"value", and "priority", "weight", "port" as
             stored}: its edit row, 2.1.4.15), for A/AAAA "ptr", "ptr_note", and for A/AAAA/CNAME "link"
             (the landing page's link, 1.4.2.4, or None), "subnets" (the subnets it answers, or "all", 2.1.4.17;
             an A or AAAA record for some subnets has its PTR in their answers only, "ptr_scope": "subnets")}],
             "status" (sync message), "subnets" ([{"cidr", "label"}]: the host's LAN and the plan's subnets, for the
             Subnets column; [] for a reverse zone), "default" (what a new record starts with: default_reach)}.
    Fails:   ValidationError "unknown zone"; OSError or yaml.YAMLError from load_vars or sync_status.
    Feeds:   agent route GET /v1/zones/<key> (fabric-agent, src/agent/, called by the web UI).
    """
    data = load_vars()
    zone = (data.get("dns") or {}).get(key)
    if zone is None:
        raise ValidationError("unknown zone")
    records = []
    for rtype in RECORD_TYPES:
        for idx, rec in enumerate(zone.get(rtype) or []):
            entry = {"type": rtype, "index": idx, "name": rec.get("name") or "",
                     "value": format_value(rtype, rec), "fabric": fabric_record(data, key, rtype, rec)}
            entry["edit"] = {"value": str(rec.get(EDIT_VALUE[rtype], "")),      # its edit row (2.1.4.15)
                             **{k: str(rec[k]) for k in ("priority", "weight", "port") if k in rec}}
            entry["subnets"] = reach(rec)                                        # the subnets it answers (2.1.4.17)
            if rtype in ("A", "AAAA", "CNAME"):
                entry["link"] = rec.get("link") or None
            if rtype in ("A", "AAAA"):
                rzone, label = ptr_for_ip(rec.get("ip"))
                entry["ptr"] = f"{label}.{rzone}" if rzone else ""
                entry["ptr_note"] = "" if rzone else label
                entry["ptr_scope"] = "subnets" if rzone and entry["subnets"] != ALL else "all"
            records.append(entry)
    name = zone_name(data, key)
    try:                                   # the subnets a record may answer (2.1.4.17): the host's LAN, the plan's
        plan = load_plan_cache() or {}
    except (OSError, ValueError):
        plan = {}
    offered = [] if key.endswith(".arpa") else offered_subnets(data, plan)
    return {"key": key, "name": name, "records": records, "status": sync_status(name)[1], "subnets": offered,
            "default": default_reach(data, offered) if offered else ALL}
