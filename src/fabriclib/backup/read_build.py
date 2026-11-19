import os


def read_build(fabric_dir):
    """Purpose: what a code tree was built as, from its BUILD file (written by the package build: "package: fabricctl
             <version>", "commit: <sha>"): the installed tree (<install root>/fabric/BUILD) or the
             package's (/usr/lib/fabricctl/fabric/BUILD).
    Inputs:  fabric_dir — the tree's folder (<install root>/fabric, or the package's fabric/).
    Returns: {"version": "0.10.1" (or "0.10.1~git…" for a candidate), "commit": sha}; "?" for each one the tree's
             BUILD does not give (or it has no BUILD).
    Fails:   never.
    Feeds:   make_backup (the manifest), run_restore_command (the package's version, the install's)."""
    try:
        with open(os.path.join(fabric_dir, "BUILD")) as f:
            build = dict(line.split(":", 1) for line in f.read().splitlines() if ":" in line)
    except OSError:
        build = {}
    package = build.get("package", "").split()
    return {"version": package[-1] if package else "?", "commit": build.get("commit", "").strip() or "?"}
