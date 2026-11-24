import os

from fabriclib.secrets.constants import MARKER


def secrets_in_openbao(secrets_file):
    """Purpose: Whether fabric's secrets were imported into OpenBao, i.e. a missing secrets file no longer
             means "no secrets".
    Inputs:  secrets_file — path of fabric-secrets.yml; the marker (secrets.openbao) is looked for in its
             directory.
    Returns: True if the marker exists, else False.
    Fails:   never — a plain existence check.
    Feeds:   load_secrets, save_secrets, setup/deploy_config.py run, backup/make_backup (a cold bundle).
    """
    return os.path.exists(os.path.join(os.path.dirname(secrets_file), MARKER))
