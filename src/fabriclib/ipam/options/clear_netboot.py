from fabriclib.common.errors import ValidationError
from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.netboot_targets import netboot_targets


def clear_netboot(v, actor, target, site="", secrets=None, container="samba", source="cli"):
    """Purpose: switch a netboot preset off for a VLAN (each of its subnets), a subnet or a reservation (manual
             1.10.4.25).
    Inputs:  v — fabric vars; actor — who asks (audit); target — a VLAN ID, a subnet's name or network, or an
             address; site — whose plan ("" this site's); secrets, container, source — as edit_options.
    Returns: edit_options' result; result = {"targets": [labels of those that had a preset]}.
    Fails:   ValidationError: what netboot_targets refuses; none of them has a preset; what edit_options refuses.
    Feeds:   run_option_command (netboot off), agent route POST /v1/ipam/netboot."""
    def change(plan):
        targets = [t for t in netboot_targets(plan, target) if t[1].get("netboot")]
        if not targets:
            raise ValidationError(f"{target}: no netboot preset is on there")
        return ([make(None) for _, _, make in targets], {"targets": [t[0] for t in targets]},
                ", ".join(t[0] for t in targets), [])
    return edit_options(v, actor, site, "IPAM_NETBOOT_OFF", change, secrets, container, source)
