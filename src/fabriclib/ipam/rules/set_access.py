from fabriclib.common.errors import ValidationError
from fabriclib.common.write_audit import write_audit
from fabriclib.ipam.common.edit_plan import edit_plan
from fabriclib.ipam.rules.access_warnings import access_warnings
from fabriclib.ipam.rules.change_access_rows import change_access_rows
from fabriclib.ipam.rules.check_cut_off import check_cut_off
from fabriclib.ipam.rules.rule_networks import rule_networks


def set_access(v, actor, network, actions, site="", force=False, whole=False, secrets=None, container="samba",
               source="cli", caller=None):
    """Purpose: what one network of a site reaches, set (manual 1.10.4.48.10, 1.10.4.48.11, decision 2.1.10.63):
             `fabricctl ipam access set`, the console's Save on a network's tab, the agent's
             post.networks.access.<network>. Checked (change_access_rows), the host's VLAN guarded (2.1.10.57), then
             the site's rows written in place of the old ones through edit_plan (the grant's networks right `plan`,
             the audit IPAM_ACCESS_SET; IPAM_RULE_FORCED when --force took a cut-off).
    Inputs:  v — fabric vars; actor — who asks; network — a VLAN, "fabric" or "any"; actions — {service or "all":
             action}; site — "" this site, or another the caller's grants reach; force — take a cut-off (the command
             line, as root, only); whole — actions is the network's whole row (the console's tab); secrets,
             container, source ("cli" or "web"), caller — as edit_plan.
    Returns: edit_plan's result; result = {"network", "row" (its services after), "did", "forced" (bool)}.
    Fails:   ValidationError: what change_access_rows refuses; a cut-off without --force; --force from the console or
             a signed-in person; what edit_plan refuses.
    Feeds:   ipam/cli/run_plan_change (access set), agent/post_networks."""
    if force and (source != "cli" or caller is not None):
        raise ValidationError("--force is taken only on the command line, as root on the host")
    forced = []

    def change(plan, read, org):
        own = plan["site"] == v.get("site_name")
        nets = rule_networks(v if own else {}, plan)
        rows, after, net, did = change_access_rows(plan, nets["host_vlan"], network, actions, whole)
        cut = check_cut_off(after, nets["host_vlan"])
        if cut and not force:
            raise ValidationError(cut)
        if cut:
            forced.append(cut)
        changes = [{"do": "set", "what": "rules", "site": plan["site"], "fields": {"rules": rows}}]
        result = {"network": net, "row": after[net], "did": did, "forced": bool(cut)}
        return changes, result, did, access_warnings(after, nets)
    out = edit_plan(v, actor, site, "IPAM_ACCESS_SET", change, secrets, container, source, caller=caller)
    if forced:
        write_audit(actor, "IPAM_RULE_FORCED", f"site={out['site']} {forced[0]}", source)
    return out
