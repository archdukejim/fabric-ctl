from fabriclib.ipam.common.edit_options import edit_options
from fabriclib.ipam.options.check_netboot import check_netboot
from fabriclib.ipam.options.netboot_targets import netboot_targets


def set_netboot(v, actor, target, preset, site="", secrets=None, container="samba", source="cli"):
    """Purpose: switch a netboot preset on (or replace it) for a VLAN, a subnet or a reservation (decision 2.1.10.25,
             manual 1.10.4.25): stored as the named option "netboot" on each subnet or the address, rendered as Kea's
             client classes at the apply and the plan poll.
    Inputs:  v — fabric vars; actor — who asks (audit); target — a VLAN ID, a subnet's name or network, or an
             address; preset — {"server", "bios", "uefi", "arm64", "ipxe", "http"}; site — whose plan ("" this site's);
             secrets, container, source — as edit_options.
    Returns: edit_options' result; result = {"targets": [labels], "preset": the preset as stored}; warnings =
             check_netboot's.
    Fails:   ValidationError: what check_netboot or netboot_targets refuses; what edit_options refuses.
    Feeds:   run_option_command (netboot on), agent route POST /v1/ipam/netboot."""
    checked, warnings = check_netboot(preset)

    def change(plan):
        targets = netboot_targets(plan, target)
        detail = " ".join(f"{k}={x}" for k, x in checked.items())
        return ([make(checked) for _, _, make in targets], {"targets": [t[0] for t in targets], "preset": checked},
                f"{', '.join(t[0] for t in targets)} {detail}", warnings)
    return edit_options(v, actor, site, "IPAM_NETBOOT_ON", change, secrets, container, source)
