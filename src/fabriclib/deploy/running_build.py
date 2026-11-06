import os

from fabriclib.system.version_info import version_info

STAMP = "running-build"


def _this_build():
    """Purpose: what identifies the code now installed.
    Inputs:  none.
    Returns: str, its version and build stamp.
    Fails:   OSError from reading them.
    Feeds:   build_changed, record_build."""
    info = version_info()
    return f"{info['version']} {info['build']}\n"


def build_changed(config_dir):
    """Purpose: whether fabric's long-running host services still run an older build (decision 2.1.1.83): a package
             update replaces the files under them, and a Python service keeps what it imported until it restarts.
    Inputs:  config_dir — the install's config folder.
    Returns: bool; True when no build has been recorded yet.
    Fails:   OSError from reading.
    Feeds:   apply_deployment."""
    try:
        with open(os.path.join(config_dir, STAMP)) as f:
            return f.read() != _this_build()
    except FileNotFoundError:
        return True


def record_build(config_dir):
    """Purpose: the services have been told to restart on this build. Only bookkeeping, after the apply's work is
             done, so a failure here says so and does not turn a finished apply into a failed one (2.3.1.53): the next
             apply finds no record and restarts them once more, which is safe.
    Inputs:  config_dir — the install's config folder.
    Returns: bool, whether it was recorded.
    Fails:   never; it prints what went wrong.
    Feeds:   apply_deployment."""
    try:
        with open(os.path.join(config_dir, STAMP), "w") as f:
            f.write(_this_build())
    except OSError as exc:
        print(f"Warning: could not record this build ({exc}): the next apply restarts fabric's services once more")
        return False
    return True
