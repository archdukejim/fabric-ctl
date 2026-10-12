import os

from fabriclib.secrets.load_secrets import load_secrets


def adguard_password(v):
    """Purpose: fabric-agent's password in AdGuard Home (adguard_api_password, manual 1.12.3.4), read from fabric's
             secrets of this install (the file, or OpenBao).
    Inputs:  v — fabric vars (deploy_base_dir).
    Returns: str.
    Fails:   ValidationError from load_secrets (OpenBao locked or refusing); KeyError when the secret is not there yet
             (no apply has run since 0.7.0 was installed).
    Feeds:   dns_filter/refresh_lists, apply_dns_filter, ingest_dns_log, set_filter_list."""
    path = os.path.join(v.get("deploy_base_dir") or "/opt", "fabric", "config", "fabric-secrets.yml")
    return load_secrets(path, v)["adguard_api_password"]
