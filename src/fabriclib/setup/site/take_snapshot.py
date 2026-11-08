import os


def take_snapshot(top):
    """Purpose: what the install folder holds before the site's questions, so a cancelled setup can leave it exactly so
             (manual 1.3.6.3: "with nothing changed"): the questions save settings as they go (finish_vars).
    Inputs:  top — the install's folder (SetupContext.target_dir; absent on a new install).
    Returns: {"dirs": set of paths, "files": {path: bytes}}; every file's content, the folder of a new install being
             empty or nearly so.
    Fails:   OSError reading a file.
    Feeds:   setup/site/guided_site; setup/site/restore_snapshot reads it."""
    dirs, files = set(), {}
    for folder, _subdirs, names in os.walk(top):
        dirs.add(folder)
        for name in names:
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    files[path] = f.read()
    return {"dirs": dirs, "files": files}
