from fabriclib.common.errors import ValidationError
from fabriclib.directory.list_machines import list_machines
from fabriclib.directory.list_people import list_people
from fabriclib.domain.domain_facts import domain_facts
from fabriclib.domain.list_groups import list_groups
from fabriclib.domain.list_ous import list_ous
from fabriclib.samba.domain_status import domain_status
from fabriclib.samba.replication_status import replication_status


def directory_overview(v, secrets=None, container="samba"):
    """Purpose: the Directory's Overview (manual 1.6.12.3): the AD domain and its NetBIOS name, its functional level,
             its DCs (writable or read-only), who holds the five roles (named plainly), this DC's replication, the
             sites, and how many people, groups, computers and OUs there are.
    Inputs:  v — rendered vars; secrets — fabric's secrets (default: load_secrets(), through the reads); container —
             the DC's container.
    Returns: {"status": domain_status, "level", "dcs", "replication": replication_status, "sites": [names, from the
             site-<name> groups], "counts": {"people", "groups", "computers", "ous"}, "error": "" or why the
             directory could not be read (the facts, sites and counts then empty)}.
    Fails:   never for a DC that does not answer (error says so).
    Feeds:   agent route GET /v1/directory (domain:read)."""
    out = {"status": domain_status(v), "level": "", "dcs": [], "replication": replication_status(container),
           "sites": [], "counts": {}, "error": ""}
    try:
        facts = domain_facts(v, secrets, container)
        groups = list_groups(v, secrets, container).get("groups") or []
        out.update(level=facts.get("level", ""), dcs=facts.get("dcs") or [],
                   sites=sorted(g["name"][len("site-"):] for g in groups if g.get("name", "").startswith("site-")),
                   counts={"people": len(list_people(v, secrets).get("users") or []), "groups": len(groups),
                           "computers": len(list_machines(v, secrets, container)),
                           "ous": len(list_ous(v, secrets, container).get("ous") or [])})
    except ValidationError as exc:
        out["error"] = str(exc)
    return out
