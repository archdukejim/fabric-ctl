from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.dns.common.fabric_record import fabric_record
from fabriclib.dns.constants import RECORD_TYPES
from fabriclib.dns.format_value import format_value
from fabriclib.dns.ptr_for_ip import ptr_for_ip
from fabriclib.dns.sync_status import sync_status
from fabriclib.dns.zone_name import zone_name
from fabriclib.dns.split.offered_subnets import offered_subnets
from fabriclib.dns.split.zone_networks import zone_networks
from fabriclib.ipam.common.plan_cache import load_plan_cache

# the stored field a record's one value is (its edit row, 2.1.4.15)
EDIT_VALUE = {"A": "ip", "AAAA": "ip", "CNAME": "canonical", "MX": "exchange", "TXT": "text", "SRV": "target"}


def _records(data, key, home, in_split):
    """Purpose: one tab's records for the zone page (the zone's own, or a split's, 2.1.4.18).
    Inputs:  data — settings; key — the zone's key; home — the tab's record lists; in_split — True for a split.
    Returns: [record entry] as zone_detail describes them.
    Fails:   never.
    Feeds:   zone_detail."""
    records = []
    for rtype in RECORD_TYPES:
        for idx, rec in enumerate(home.get(rtype) or []):
            entry = {"type": rtype, "index": idx, "name": rec.get("name") or "", "value": format_value(rtype, rec),
                     "fabric": None if in_split else fabric_record(data, key, rtype, rec)}
            entry["edit"] = {"value": str(rec.get(EDIT_VALUE[rtype], "")),      # its edit row (2.1.4.15)
                             **{k: str(rec[k]) for k in ("priority", "weight", "port") if k in rec}}
            if rtype in ("A", "AAAA", "CNAME"):
                entry["link"] = rec.get("link") or None
            if rtype in ("A", "AAAA"):
                rzone, label = ptr_for_ip(rec.get("ip"))
                entry["ptr"] = f"{label}.{rzone}" if rzone else ""
                entry["ptr_note"] = "" if rzone else label
                entry["ptr_scope"] = "split" if in_split and rzone else "all"     # a split's: its networks only
            records.append(entry)
    return records


def zone_detail(key):
    """Purpose: One zone for the zone page: its records with display values, where each A/AAAA record's automatic PTR
             goes (or why there is none), BIND's sync status, and its networks and split tabs (decision 2.1.4.18).
    Inputs:  key — str zone key in `dns:`. Reads vars.yaml and the plan's copy; runs sync_status (docker exec rndc).
    Returns: {"key", "name", "records" (the All networks tab): [{"type", "index", "name", "value", "fabric"
             ({"service", "setting"} for one of fabric's own names, 2.1.2.22, else None), "edit" ({"value", and
             "priority", "weight", "port" as stored}: its edit row, 2.1.4.15), for A/AAAA "ptr", "ptr_note",
             "ptr_scope" ("split": answered in the split's networks only), and for A/AAAA/CNAME "link" (the landing
             page's link, 1.4.2.4, or None)}], "status" (sync message), "networks" ("all" or [CIDR]), "offered"
             ([{"cidr", "label"}]: the host's LAN and the plan's subnets; [] for a reverse zone), "splits"
             ([{"index", "subnets", "records"}]), "mappable" (False for the site's own domain and a reverse zone),
             "splittable" (False for a reverse zone)}.
    Fails:   ValidationError "unknown zone"; OSError or yaml.YAMLError from load_vars or sync_status.
    Feeds:   agent route GET /v1/zones/<key> (fabric-agent, src/agent/, called by the web UI).
    """
    data = load_vars()
    zone = (data.get("dns") or {}).get(key)
    if zone is None:
        raise ValidationError("unknown zone")
    name = zone_name(data, key)
    reverse = key.endswith(".arpa")
    try:                                   # the networks a zone may answer (2.1.4.18): the host's LAN, the plan's
        plan = load_plan_cache() or {}
    except (OSError, ValueError):
        plan = {}
    splits = [{"index": i, "subnets": list(s.get("subnets") or []), "records": _records(data, key, s, True)}
              for i, s in enumerate(zone.get("splits") or [])]
    return {"key": key, "name": name, "records": _records(data, key, zone, False), "status": sync_status(name)[1],
            "networks": zone_networks(zone), "offered": [] if reverse else offered_subnets(data, plan),
            "splits": splits, "mappable": not reverse and key != "dynamic_zone_var", "splittable": not reverse}
