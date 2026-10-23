import platform
import subprocess

MACHINES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def host_arch():
    """Purpose: this host's architecture as Debian and Docker name it.
    Inputs:  none (asks dpkg, else the kernel's machine name).
    Returns: str, "amd64", "arm64" or what dpkg says for another (bundles exist only for the first two).
    Fails:   never — without dpkg the kernel's name is mapped, unknown ones returned as they are.
    Feeds:   import_bundle, run_images_command (export's default architecture)."""
    try:
        res = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    machine = platform.machine()
    return MACHINES.get(machine, machine)
