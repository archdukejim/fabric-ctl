import os

from fabriclib.common.paths import LIB_DIR

FOLDER = "setup-site"


def read_site_files(lib_dir=LIB_DIR):
    """Purpose: the site's pages, stylesheet, script and drawings: setup reads them and hands them over, so the listener
             needs nothing but its own code from the disk (manual 1.3.6.3).
    Inputs:  lib_dir — the folder holding fabriclib: installed, <lib_dir>/setup-site; in a checkout, the repository's
             templates/setup-site and static/setup-site.
    Returns: {file name: text}, without READMEs.
    Fails:   OSError when none of those folders can be read.
    Feeds:   setup/site/guided_site."""
    repo = os.path.dirname(lib_dir)
    folders = [os.path.join(lib_dir, FOLDER)]
    if not os.path.isdir(folders[0]):
        folders = [os.path.join(repo, "templates", FOLDER), os.path.join(repo, "static", FOLDER)]
    files = {}
    for folder in folders:
        for name in sorted(os.listdir(folder)):
            if name != "README.md":
                with open(os.path.join(folder, name), encoding="utf-8") as f:
                    files[name] = f.read()
    return files
