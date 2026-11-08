import os


def restore_snapshot(top, snapshot):
    """Purpose: leave the install folder as take_snapshot found it: what appeared removed, what changed put back.
    Inputs:  top — the install's folder; snapshot — take_snapshot's result.
    Returns: None.
    Fails:   OSError.
    Feeds:   setup/site/guided_site."""
    for folder, _subdirs, names in os.walk(top, topdown=False):
        for name in names:
            path = os.path.join(folder, name)
            if path not in snapshot["files"]:
                os.remove(path)
        if folder not in snapshot["dirs"]:
            os.rmdir(folder)
    for path, content in snapshot["files"].items():
        with open(path, "rb") as f:
            same = f.read() == content
        if not same:
            with open(path, "wb") as f:
                f.write(content)
