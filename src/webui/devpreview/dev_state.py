import copy
import threading

from webui.devpreview.fabric_rules import (DEVICE_NAME_RE, DEVICE_TYPES, PERMISSIONS, ROLE_NAME_RE, ValidationError,
                                           check_device_fields, check_role_fields, list_devices, ptr_for_ip,
                                           reverse_zones)
from webui.devpreview.sample_data import SAMPLE, SAMPLE_FABRIC_NAMES, SAMPLE_SLOTS


class DevState:
    """In-memory sample data; nothing leaves this process."""

    def __init__(self):
        """Purpose: Fresh in-memory copies of the sample zones, audit, TSIG keys, directory, people, issued certs and
                 vault slots; nothing leaves this process.
        Inputs:  none (deep-copies SAMPLE and SAMPLE_SLOTS).
        Returns: None.
        Fails:   never.
        Feeds:   DevHandler.state (one per process, shared by all request threads under self.lock).
        Notes:   SAMPLE_RADIUS and SAMPLE_DHCP are not copied here: do_POST changes those module-level dicts directly.
        """
        self.data = copy.deepcopy(SAMPLE)
        self.data["slots"] = copy.deepcopy(SAMPLE_SLOTS)
        self.lock = threading.Lock()
        self.toggles = {}           # the preview's own query switches for this request (fresh, off: dev_handler)
        self.flash = None           # the last action's message, for the next page (as a session holds it)
        self.pending = None         # Apply per page's store (fake_pending: the agent's PendingStore over the samples)

    def zones(self):
        """Purpose: The zone list, in the shape fabric-agent's GET /v1/zones returns.
        Inputs:  none (reads self.data["zones"]).
        Returns: [{"key": str, "name": str, "records": int, "reverse": False}].
        Fails:   never.
        Feeds:   fake_reads (GET /v1/zones).
        """
        return [{"key": k, "name": z["name"], "records": len(z["records"]), "reverse": False}
                for k, z in self.data["zones"].items()]

    def reverse(self):
        """Purpose: The reverse zones, made by the same PTR generation apply uses, over the in-memory sample records.
        Inputs:  none (reads self.data["zones"]; uses fabriclib.dns.reverse_zones when importable).
        Returns: {"zones": {...}, "skipped": [...]}; {"zones": {}, "skipped": []} without fabriclib.
        Fails:   KeyError if the "dynamic_zone_var" sample zone is gone (never: no route deletes zones); anything
                 reverse_zones raises propagates.
        Feeds:   fake_reads (GET /v1/reverse-zones).
        """
        if not reverse_zones:
            return {"zones": {}, "skipped": []}
        dns = {}
        for k, z in self.data["zones"].items():
            for t, n, v in z["records"]:
                if t in ("A", "AAAA"):
                    dns.setdefault(k, {}).setdefault(t, []).append({"name": n, "ip": v})
        return reverse_zones({"domain": self.data["zones"]["dynamic_zone_var"]["name"], "dns": dns})

    def zone(self, key):
        """Purpose: One sample zone with its records, in the shape fabric-agent's GET /v1/zones/<key> returns.
        Inputs:  key — a key of self.data["zones"].
        Returns: {"key", "name", "status": dev-preview note, "records": [{"type", "index", "name", "value", "fabric"
                 ({"service", "setting"} for SAMPLE_FABRIC_NAMES in the site's zone, else None), "link" (the landing
                 page's, from the zone's "links", or None)} plus "ptr"/"ptr_note" for A/AAAA when fabriclib is
                 present]}; "index" is the position in the zone's list.
        Fails:   KeyError for an unknown key (the caller checks first).
        Feeds:   fake_reads (GET /v1/zones/<key>); the index is what fake_dns's record delete expects.
        """
        z = self.data["zones"][key]
        own = SAMPLE_FABRIC_NAMES if key == "dynamic_zone_var" else {}
        return {"key": key, "name": z["name"], "status": "dev preview — sample data, not served by BIND",
                "records": [dict({"type": t, "index": i, "name": n, "value": v,
                                  "fabric": dict(zip(("service", "setting"), own[(t, n)])) if (t, n) in own else None,
                                  "link": (z.get("links") or {}).get(f"{t}|{n}")}, **self._ptr(t, v))
                            for i, (t, n, v) in enumerate(z["records"])]}

    @staticmethod
    def _ptr(rtype, value):
        """Purpose: Where an A/AAAA record's automatic PTR goes, for the zone table.
        Inputs:  rtype — record type; value — the record's address text.
        Returns: {} for other types or without fabriclib; else {"ptr": "<label>.<zone>" or "", "ptr_note": "" or why
                 there is no PTR}.
        Fails:   never — ptr_for_ip reports a bad address as a reason instead of raising.
        Feeds:   DevState.zone.
        """
        if rtype not in ("A", "AAAA") or not ptr_for_ip:
            return {}
        zone, label = ptr_for_ip(value)
        return {"ptr": f"{label}.{zone}" if zone else "", "ptr_note": "" if zone else label}

    def overview(self):
        """Purpose: Devices, roles and the RBAC vocabulary, in the shape fabric-agent's GET /v1/devices returns.
        Inputs:  none (reads self.data["directory"]; needs fabriclib's list_devices).
        Returns: {"devices", "roles" (sorted by priority then name), "types", "permissions"}; None without fabriclib.
        Fails:   never in practice — anything list_devices raises propagates.
        Feeds:   fake_reads (GET /v1/devices).
        """
        if not list_devices:
            return None
        d = self.data["directory"]
        return {"devices": list_devices({}, d), "roles": sorted(d["roles"], key=lambda r: (r["priority"], r["name"])),
                "types": DEVICE_TYPES, "permissions": {k: list(v) for k, v in PERMISSIONS.items()}}

    def save(self, kind, name, fields):
        """Purpose: Create or edit a device or role in memory, validated by the real fabriclib rules, and log it.
        Inputs:  kind — "devices", anything else means roles; name — device/role name (new names are checked against
                 DEVICE_NAME_RE / ROLE_NAME_RE, "_new" is refused for devices); fields — the agent's fields, as the
                 console sends them: devices type, owner, description, enabled, macs (list), roles (list); roles
                 description, vlan, priority, permissions (list).
        Returns: None; self.data["directory"] and role memberships are updated, an audit line is added.
        Fails:   ValidationError from check_device_fields / check_role_fields or for a bad new name. Only called when
                 fabriclib imported (NameError otherwise).
        Feeds:   fake_directory (POST /v1/devices…, /v1/roles…).
        """
        d = self.data["directory"]
        form = fields
        if kind == "devices":
            f = check_device_fields({"type": form.get("type"), "owner": form.get("owner"),
                                     "description": form.get("description"), "enabled": bool(form.get("enabled")),
                                     "macs": list(form.get("macs") or []), "roles": list(form.get("roles") or [])},
                                    d, name)
            entry = next((x for x in d["devices"] if x["name"] == name), None)
            if entry is None:
                if not DEVICE_NAME_RE.match(name) or name == "_new":
                    raise ValidationError("device name: a host name label — lowercase letters, digits and '-'")
                entry = {"name": name, "certs": []}
                d["devices"].append(entry)
            entry.update(type=f["type"], enabled=f["enabled"], macs=f["macs"], description=f["description"],
                         owner=f"uid={f['owner']},ou=users" if f["owner"] else "")
            for r in d["roles"]:
                r["members"] = [m for m in r["members"] if m != name] + ([name] if r["name"] in f["roles"] else [])
        else:
            f = check_role_fields({"description": form.get("description"), "vlan": form.get("vlan"),
                                   "priority": form.get("priority"),
                                   "permissions": list(form.get("permissions") or [])})
            entry = next((x for x in d["roles"] if x["name"] == name), None)
            if entry is None:
                if not ROLE_NAME_RE.match(name):
                    raise ValidationError("role name: lowercase letters, digits, '-' and '_'")
                entry = {"name": name, "members": []}
                d["roles"].append(entry)
            entry.update(f)
        self.log("DEVICE_SAVE" if kind == "devices" else "ROLE_SAVE", f"{name} (in memory)")

    def log(self, action, detail):
        """Purpose: Add a dev-preview line to the in-memory audit log (newest first).
        Inputs:  action — str action name such as "DNS_ADD"; detail — str.
        Returns: None.
        Fails:   never.
        Feeds:   fake_reads (GET /v1/audit).
        """
        self.data["audit"].insert(0, f"[dev] User: dev (web) | Action: {action} | {detail}\n")
