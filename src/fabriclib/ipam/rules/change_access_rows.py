from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.vlan_refs import parse_vlan_ref, vlan_ref
from fabriclib.ipam.rules.access_table import access_table
from fabriclib.ipam.rules.constants import ACTIONS, ALL, ANY, FABRIC, SERVICES


def _network(word, table):
    """Purpose: a network as typed, as the table names it.
    Inputs:  word — "fabric", "any" or a VLAN ("20", "20@branch"); table — access_table's shape.
    Returns: str, the table's key.
    Fails:   ValidationError naming what the site has.
    Feeds:   change_access_rows."""
    text = str(word or "").strip().lower()
    if text in (FABRIC, ANY):
        return text
    try:
        vid, location = parse_vlan_ref(text)
        ref = vlan_ref({"id": vid, "location": location})
    except ValidationError:
        ref = None
    if ref not in table or ref in (FABRIC, ANY):
        vlans = [k for k in table if k not in (FABRIC, ANY)]
        raise ValidationError(f"network {word!r}: a VLAN of the site ({', '.join(vlans) or 'none yet'}), fabric "
                              "(the other sites) or any (every address)")
    return ref


def change_access_rows(plan, host_vlan, network, actions, whole=False):
    """Purpose: one network's services set in a site's access table (manual 1.10.4.48.10, decision 2.1.10.63): checked,
             then the rows to keep, one per network that differs from its default. Pure: set_access writes them, the
             dev preview keeps them in memory.
    Inputs:  plan — the site's plan (site_plan's); host_vlan — the host's VLAN's reference, or None; network — as
             typed: a VLAN, "fabric" or "any"; actions — {service or "all": "allow" | "deny"}; whole — True when
             actions is the network's whole row (the console's tab: a service left out is denied).
    Returns: (rows to keep [{"net", service: action}], the table after, the network's key, what changed as str).
    Fails:   ValidationError: an unknown network, service or action; no service given; a change that changes nothing.
    Feeds:   set_access, the dev preview (webui/devpreview/fake_ipam)."""
    table = access_table(plan, host_vlan)
    defaults = access_table({**(plan or {}), "rules": [], "rules_kept": True}, host_vlan)
    net = _network(network, table)
    if not actions and not whole:
        raise ValidationError("no service given: name one of " + ", ".join([*SERVICES, ALL]))
    row = {s: "deny" for s in SERVICES} if whole else dict(table[net])
    for service, action in actions.items():
        svc, act = str(service or "").strip().lower(), str(action or "").strip().lower()
        if svc != ALL and svc not in SERVICES:
            raise ValidationError(f"service {service!r}: one of {', '.join([*SERVICES, ALL])}")
        if act not in ACTIONS:
            raise ValidationError(f"{action!r}: allow or deny")
        for s in SERVICES if svc == ALL else [svc]:
            row[s] = act
    changed = [s for s in SERVICES if row[s] != table[net][s]]
    if not changed:
        raise ValidationError(f"nothing to change: {net} already " + ", ".join(
            f"{s} {row[s]}" for s in SERVICES if s in actions or ALL in actions or whole))
    after = {**table, net: row}
    rows = [{"net": k, **after[k]} for k in after if after[k] != defaults[k]]
    did = f"{net}: " + ", ".join(f"{s} {row[s]}" for s in changed)
    return rows, after, net, did
