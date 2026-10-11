import os


def resolver_paths(v):
    """Purpose: the BIND resolver's folders and files under the deploy base (manual 1.12.2.4).
    Inputs:  v — fabric vars (deploy_base_dir, default /opt).
    Returns: {"root", "config", "log", "cache", "tls" (the DNS name's certificate, 1.12.2.16): folders; "lists": where
             a 0.8.0 candidate kept its converted lists, removed by deploy_resolver (the lists are AdGuard's: 1.12.3)}.
    Fails:   never.
    Feeds:   dns_filter/deploy_resolver, dns_filter/ingest_dns_log."""
    root = os.path.join(v.get("deploy_base_dir") or "/opt", "resolver")
    return {"root": root, "config": os.path.join(root, "config"), "lists": os.path.join(root, "lists"),
            "log": os.path.join(root, "log"), "cache": os.path.join(root, "cache"), "tls": os.path.join(root, "tls")}
