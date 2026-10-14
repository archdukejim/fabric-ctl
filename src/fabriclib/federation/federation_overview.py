from fabriclib.common.errors import ValidationError
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.common.sites_shown import sites_shown
from fabriclib.federation.common.visible_plan import visible_plan
from fabriclib.federation.read_address_plan import read_address_plan
from fabriclib.federation.site_roles import site_roles
from fabriclib.samba.list_conflicts import list_conflicts
from fabriclib.samba.replication_status import replication_status

# each site's default write limits in the domain (manual 1.6.3.6): who, what it may write, beyond that
LIMITS = [
    ("fabric-agent-<site>", "its own OU=<site> (people, groups, machines, devices, roles, networks, sudo rules, its "
     "GPOs), never its service accounts", "read only"),
    ("<site>-admins (the site helpdesk)", "its own site's people: add, unlock, reset a password, disable or enable; "
     "never one who holds a role (2.1.9.21)", "read only"),
    ("<site>-<role> (granted from above)", "what the role gives at that site: ou-admins, machine-admins, gpo-admins, "
     "windows-admins, fabric-admins; never their own memberships", "read only"),
    ("fabric-agent-<root>", "as a site's, plus OU=organisation, the domain's trust GPO and the password policy", ""),
    ("fabric-keycloak-<site>", "its site's people and groups (sign-in, password changes)", "read only"),
    ("fabric-radius-<site>", "nothing", "read only"),
]


def federation_overview(v):
    """Purpose: what the Federation tab shows (manual 1.9.8.9, 1.6.5.22 S8.5): this install's place, the sites that
             joined here with their DC types, this DC's replication with the others and AD's `CNF:` conflict
             objects, the default write limits, the roles granted at this site and the sites below it (2.1.9.21), and
             the address plan with its overlaps — this site's and the sites' below it only (2.1.9.22: the top sees
             all; an overlap with a site not shown is only counted).
    Inputs:  v — fabric vars (site_name, and what read_address_plan reads).
    Returns: {"site", "upstream" (record or None), "sites": [{name, domain, address, parent, dc, id_range, joined,
             via}], "replication": replication_status(), "conflicts": [DN], "limits": LIMITS rows, "plan": [network],
             "overlaps": [network_conflicts items with "site"], "hidden_overlaps": int, "plan_error": "", "roles":
             site_roles' "sites" list, "roles_error": ""}.
    Fails:   yaml/OSError from load_registry for a malformed registry (the domain's own failures are shown, not raised).
    Feeds:   agent route GET /v1/federation (federation:read)."""
    registry = load_registry()
    sites = [{"name": name, **{k: rec.get(k, "") for k in ("domain", "address", "parent", "dc", "id_range", "joined",
                                                           "via")}}
             for name, rec in sorted(registry.get("sites", {}).items())]
    out = {"site": v.get("site_name", ""), "upstream": registry.get("upstream") or None, "sites": sites,
           "replication": replication_status(), "conflicts": list_conflicts(),
           "limits": [list(row) for row in LIMITS], "plan": [], "overlaps": [], "hidden_overlaps": 0,
           "plan_error": "", "roles": [], "roles_error": ""}
    try:
        out["roles"] = site_roles(v)["sites"]
    except ValidationError as e:
        out["roles_error"] = str(e)
    try:
        plan = read_address_plan(v)
    except ValidationError as e:
        out["plan_error"] = str(e)
        return out
    out.update(visible_plan(plan, sites_shown(v, registry)))
    return out
