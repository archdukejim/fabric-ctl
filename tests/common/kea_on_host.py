"""A Kea file the tests write for their bridge's `eth0`, made checkable on this host (2.3.1.53, 2.3.1.56).

Kea's real check (fabriclib.dhcp.check_kea_config) runs on the host's network and refuses an interface that is not
there; a runner may have no `eth0` (GitHub's, the build VM's `lab` and `wan`). So the check is given a name the host
has; all else it reads is the file's. The test's own Kea still serves its bridge's `eth0`."""
import socket

HOST_IFACE = next((n for _, n in socket.if_nameindex() if n != "lo"), "lo")


def on_host(text):
    """The file's text with `"eth0"` named as HOST_IFACE, for Kea's real check only."""
    return text.replace('"eth0"', f'"{HOST_IFACE}"')


def check_on_host():
    """Kea's real check, given the file on_host, put where fabric's own code calls it (check_kea_files, used by
    deploy_kea and the apply; edit_dhcp, used by the dhcp commands). Returns that check, for the test's own calls."""
    import fabriclib.dhcp.check_kea_files as check_kea_files_module
    import fabriclib.dhcp.common.edit_dhcp as edit_dhcp_module
    from fabriclib.dhcp.check_kea_config import check_kea_config as real_check

    def check_kea_config(image, name, text):
        return real_check(image, name, on_host(text))

    check_kea_files_module.check_kea_config = check_kea_config
    edit_dhcp_module.check_kea_config = check_kea_config
    return check_kea_config
