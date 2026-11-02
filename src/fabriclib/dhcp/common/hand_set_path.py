import os


def hand_set_path(v):
    """Purpose: where the last apply keeps the addresses set by hand for the hourly cleanup (2.1.10.22): next to
             Kea's folders, in none that a container mounts.
    Inputs:  v — settings (deploy_base_dir).
    Returns: str, <deploy base>/kea/hand-set.json.
    Fails:   KeyError without deploy_base_dir.
    Feeds:   dhcp/keep_hand_set_addresses, dhcp/clean_dhcp_names."""
    return os.path.join(v["deploy_base_dir"], "kea", "hand-set.json")
