import os


def adguard_paths(v):
    """Purpose: AdGuard Home's folders and files under the deploy base (manual 1.12.3.3).
    Inputs:  v — fabric vars (deploy_base_dir, default /opt).
    Returns: {"root", "conf" (its AdGuardHome.yaml, read-write to it), "work" (its data), "lists" (fabric's copies of
             the lists, read-only to it), "tls" (the certificate for *.filter.<domain>): folders; "config": its
             AdGuardHome.yaml; "state": the lists' state (fabric's, outside what AdGuard reads); "catalogue":
             AdGuard's list catalogue as the lists job kept it; "render": fabric's record of its last render (root
             only: the password's hash and the restart check)}.
    Fails:   never.
    Feeds:   dns_filter/deploy_adguard, update_lists, fetch_catalogue, filter_overview, show_filter_status."""
    root = os.path.join(v.get("deploy_base_dir") or "/opt", "dnsfilter")
    return {"root": root, "conf": os.path.join(root, "conf"), "work": os.path.join(root, "work"),
            "lists": os.path.join(root, "lists"), "tls": os.path.join(root, "tls"),
            "config": os.path.join(root, "conf", "AdGuardHome.yaml"), "state": os.path.join(root, "state.json"),
            "catalogue": os.path.join(root, "catalogue.json"), "render": os.path.join(root, "render.json")}
