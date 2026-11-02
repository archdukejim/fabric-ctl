from fabriclib.dhcp.kea_option_data import kea_option_data


def kea_client_classes(classes):
    """Purpose: Kea's client-classes list from dhcp.client_classes (as normalize_client_classes returns them).
    Inputs:  classes — list of {name, test, options, next_server, server_hostname, boot_file_name, additional,
             marker}, or None.
    Returns: list of Kea client-class dicts: name, test, option-data, and next-server / server-hostname /
             boot-file-name when set (network boot); only-in-additional-list for an additional class (Kea 3.0:
             evaluated only where a subnet's evaluate-additional-classes names it); a marker is {name} alone (no test:
             a reservation assigns it). The last two are fabric's netboot classes (2.1.10.25).
    Fails:   never.
    Feeds:   jinja_env global kea_client_classes (kea/kea-dhcp4.conf.j2)."""
    out = []
    for c in classes or []:
        if c.get("marker"):
            out.append({"name": c["name"]})
            continue
        entry = {"name": c["name"], "test": c["test"], "option-data": kea_option_data([], c.get("options"))}
        if c.get("additional"):
            entry["only-in-additional-list"] = True
        for key, kea in (("next_server", "next-server"), ("server_hostname", "server-hostname"),
                         ("boot_file_name", "boot-file-name")):
            if c.get(key):
                entry[kea] = c[key]
        out.append(entry)
    return out
