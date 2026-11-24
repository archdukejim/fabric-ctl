import os

from fabriclib.backup.bundle_name import PATTERN
from fabriclib.backup.make_bundle import FOLDER
from fabriclib.common.errors import NotFound, ValidationError


def backup_file(name, folder=FOLDER):
    """Purpose: a bundle the console names, as a path in the backups folder (manual 1.3.7.9): only a bundle's own file
             name is taken, never a path, so nothing outside the folder can be read or restored.
    Inputs:  name — the file name the console sent; folder — the backups folder.
    Returns: its path.
    Fails:   ValidationError for a name that is not a bundle's; NotFound for one that is not in the folder.
    Feeds:   agent/get_backup (download), agent/post_backup (restore)."""
    if not isinstance(name, str) or not PATTERN.match(name):
        raise ValidationError("file: the name of a bundle in /var/backups/fabric")
    path = os.path.join(folder, name)
    if not os.path.isfile(path):
        raise NotFound(f"no bundle {name}")
    return path
