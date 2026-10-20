import os
import re

import yaml

from fabriclib.deploy.deploy_paths import JINJA_DIR
from fabriclib.setup.common.retired_settings import RETIRED_SETTINGS
from fabriclib.setup.errors import SetupError


def _fabric_keys(jinja_dir):
    """Purpose: the names of fabric's settings: the top-level keys of the settings' template (as the entry-point
             inventory reads them, 3.1.2.5.1), and the retired ones an older file may hold.
    Inputs:  jinja_dir — the templates folder (vars.yaml.j2 in it).
    Returns: set of str.
    Fails:   OSError reading the template.
    Feeds:   read_vars_file."""
    with open(os.path.join(jinja_dir, "vars.yaml.j2")) as f:
        return set(re.findall(r"^([a-z][a-z0-9_]*):", f.read(), re.M)) | set(RETIRED_SETTINGS)


def read_vars_file(path, jinja_dir=JINJA_DIR):
    """Purpose: read the settings file given to setup (`--file`, a checkout's custom-vars.yaml) and refuse one that is
             not fabric's (2.1.1.60's import, manual 1.8.5.7): damaged (not YAML), not a map of settings, a settings
             export of the console's wizard (`fabric_settings:`, which `fabricctl settings import` takes), or a map
             none of whose keys is one of fabric's settings. Keys of an older fabric are fabric's: they are listed
             and ignored later (drop_retired_settings), not refused.
    Inputs:  path — the file; jinja_dir — the templates folder (default: this install's).
    Returns: the settings (dict).
    Fails:   SetupError naming the file and why, saying nothing was changed; OSError when it cannot be read.
    Feeds:   setup/collect_vars."""
    with open(path) as f:
        text = f.read()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SetupError(f"the vars file {path} is damaged: it is not YAML ({str(e).splitlines()[0]}); "
                         "nothing was changed") from None
    if not isinstance(data, dict) or not data:
        raise SetupError(f"the vars file {path} holds no settings (a YAML map of fabric's settings); nothing was "
                         "changed")
    if "fabric_settings" in data:
        raise SetupError(f"{path} is a settings file of the console's wizard: import it with `sudo fabricctl settings "
                         "import` once fabric is installed (1.8.5.4); nothing was changed")
    if not set(map(str, data)) & _fabric_keys(jinja_dir):
        raise SetupError(f"{path} is not a fabric vars file: none of its keys is one of fabric's settings; nothing "
                         "was changed")
    return data
