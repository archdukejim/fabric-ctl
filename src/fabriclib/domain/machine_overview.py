from fabriclib.common.errors import ValidationError
from fabriclib.directory.list_devices import list_devices
from fabriclib.directory.list_machines import list_machines
from fabriclib.domain.list_groups import list_groups
from fabriclib.domain.list_ous import list_ous
from fabriclib.grants.grant_request import grant_request

# what a computer's page shows of an 802.1X device: nothing a person could not read on the device's own page
DEVICE_FIELDS = ("name", "type", "enabled", "macs", "roles", "vlan")


def machine_overview(v, name, secrets=None, container="samba"):
    """Purpose: one computer as its page shows it (manual 1.6.12.6): its facts as the DC has them (type, sites, OS,
             folder, machine groups, state, last sign-in), the grants that reach it and what each gives, the 802.1X
             device of the same name, and what its actions may choose from (the sites, the machine groups, the folders
             under OU=machines).
    Inputs:  v — rendered vars; name — the computer's host name (any case); secrets — fabric's secrets (default:
             load_secrets(), through the reads); container — the DC's container.
    Returns: {"machine": list_machines' row, "grants": reaching_grants' rows, "devices": [{name, type, enabled, macs,
             roles, vlan}], "choices": {"sites": [names], "groups": [machine groups], "folders": [OU paths under
             machines]}}.
    Fails:   ValidationError "no machine <name> in the domain"; from run_op or grant_request (the DC not reachable).
    Feeds:   agent route GET /v1/machines/<name> (domain:read)."""
    low = str(name or "").lower()
    row = next((m for m in list_machines(v, secrets, container) if m.get("name") == low), None)
    if row is None:
        raise ValidationError(f"no machine {name} in the domain")
    grants = grant_request(v, {"op": "reaching", "machine": low}, container).get("grants") or []
    groups = [g.get("name", "") for g in list_groups(v, secrets, container).get("groups") or []]
    folders = [o["path"] for o in list_ous(v, secrets, container).get("ous") or []
               if o.get("path") == "machines" or str(o.get("path", "")).startswith("machines/")]
    devices = [{k: d.get(k) for k in DEVICE_FIELDS} for d in list_devices(v) if str(d.get("name", "")).lower() == low]
    return {"machine": row, "grants": grants, "devices": devices,
            "choices": {"sites": sorted(g[len("site-"):] for g in groups if g.startswith("site-")),
                        "groups": sorted(g for g in groups if g.startswith("hosts-")), "folders": sorted(folders)}}
