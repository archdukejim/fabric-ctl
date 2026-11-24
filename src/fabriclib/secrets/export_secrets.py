import os

import yaml

from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.vault.common.write_private_file import write_private_file


def export_secrets(secrets_file, dest, v=None):
    """Purpose: Write a root-only copy of fabric's secrets (from wherever they live) for a reinstall's
             backup, which setup re-imports and shreds.
    Inputs:  secrets_file — path of fabric-secrets.yml (its directory holds the marker and vars.yaml);
             dest — output path (parent created 0700); v — fabric vars for OpenBao, default loaded from
             vars.yaml next to secrets_file.
    Returns: dest.
    Fails:   load_secrets' ValidationError (OpenBao unreachable or sealed); yaml.YAMLError for a malformed
             file; OSError.
    Feeds:   backup/make_backup (a cold bundle: the copy goes into it, in RAM until packed).
    Notes:   written atomically, root:root 0600 (write_private_file).
    """
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    write_private_file(dest, yaml.safe_dump(load_secrets(secrets_file, v), sort_keys=False), 0, 0, 0o600)
    return dest
