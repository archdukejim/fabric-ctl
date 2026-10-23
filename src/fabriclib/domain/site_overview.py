from fabriclib.common.errors import ValidationError
from fabriclib.directory.list_machines import list_machines
from fabriclib.directory.list_people import list_people
from fabriclib.directory.run_op import run_op
from fabriclib.domain.list_groups import list_groups
from fabriclib.grants.grant_request import grant_request
from fabriclib.samba.dc_count_text import dc_count_text
from fabriclib.samba.domain_sites import domain_sites
from fabriclib.samba.replication_status import replication_status
from fabriclib.secrets.load_secrets import load_secrets


def site_overview(v, secrets=None, container="samba"):
    """Purpose: the Directory's Sites (manual 1.6.12.8): each site (a `site-<name>` group, 2.1.6.72) with its people
             and machines, its DCs, the grants scoped to it (a where naming its group), and its AD site as fabric
             wrote it (DCs, subnets, site links; read-only); the domain's DCs as counts and this DC's replication.
    Inputs:  v — rendered vars; secrets — fabric's secrets (default: load_secrets()); container — the DC's container.
    Returns: {"sites": [{"name", "group", "people": [uids], "machines": [names], "dcs": [names], "grants": [names],
             "ad": ad_sites' row or None}], "dc_text" ("1 DC used, 1998 can be added"), "replication":
             replication_status, "error": "" or why the directory could not be read (the sites then empty)}.
    Fails:   never for a DC that does not answer (error says so).
    Feeds:   agent route GET /v1/sites (domain:read)."""
    out = {"sites": [], "dc_text": "", "replication": replication_status(container), "error": ""}
    try:
        secrets = secrets if secrets is not None else load_secrets()
        names = sorted(g["name"][len("site-"):] for g in list_groups(v, secrets, container).get("groups") or []
                       if g.get("name", "").startswith("site-"))
        people = list_people(v, secrets).get("users") or []
        machines = list_machines(v, secrets, container)
        ad = {s["name"]: s for s in run_op(v, secrets, "ad_sites", container=container).get("sites") or []}
        grants = grant_request(v, {"op": "list"}, container).get("grants") or []
        dcs = domain_sites(container)
    except ValidationError as exc:
        out["error"] = str(exc)
        return out
    out["dc_text"] = dc_count_text(len(dcs))
    for name in names:
        group = f"site-{name}"
        out["sites"].append({
            "name": name, "group": group,
            "people": sorted(u["uid"] for u in people if name in (u.get("sites") or [])),
            "machines": sorted(m["name"] for m in machines if name in (m.get("sites") or [])),
            "dcs": sorted(d["dc"] for d in dcs if d.get("site") == name),
            "grants": sorted(g["name"] for g in grants if group in (g.get("where") or [])),
            "ad": ad.get(name)})
    return out
