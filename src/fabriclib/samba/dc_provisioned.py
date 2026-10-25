import os


def dc_provisioned(deploy_base):
    """Purpose: whether this host's domain controller is installed: positive evidence, the marker Samba's container
             leaves once it provisioned or joined the domain (manual 1.6.5.5), never the absence of a setting.
    Inputs:  deploy_base — the install's base folder (/opt).
    Returns: bool: True when <deploy_base>/samba/data/.fabric-provisioned exists.
    Fails:   never.
    Feeds:   setup/collect_vars (a fresh install; a settings file's dc_name), setup/name_dc (an installed DC keeps its
             name, 2.1.6.65), settings/run_settings_command (`fabricctl settings import`)."""
    return os.path.exists(os.path.join(str(deploy_base), "samba", "data", ".fabric-provisioned"))
