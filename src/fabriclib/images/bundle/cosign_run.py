import subprocess

from fabriclib.common.errors import ValidationError


def cosign_run(cosign_image, args, mounts=(), network=True, home=None, timeout=300):
    """Purpose: run the pinned cosign image (decision 2.1.14.11) the way fabric runs it everywhere: read-only, every
             capability dropped, no new privileges, a small /tmp as its home.
    Inputs:  cosign_image — str, the pinned ref (vars image_cosign / the lock's cosign); args — list of str after
             `cosign`; mounts — (host path, container path, "ro"|"rw") tuples; network — False runs it with no
             network at all and never pulls (the offline check); home — a host folder mounted as cosign's home
             instead of /tmp (to keep what it writes there); timeout — seconds.
    Returns: subprocess.CompletedProcess (text), whatever cosign's exit.
    Fails:   ValidationError when cosign does not finish in time; FileNotFoundError without docker.
    Feeds:   fetch_signature, fetch_trusted_root, verify_offline."""
    cmd = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
           "--tmpfs", "/tmp:size=16m", "-e", f"HOME={'/cosign-home' if home else '/tmp'}"]
    if home:
        cmd += ["-v", f"{home}:/cosign-home:rw"]
    if not network:
        cmd += ["--network", "none", "--pull", "never"]
    for src, dst, mode in mounts:
        cmd += ["-v", f"{src}:{dst}:{mode}"]
    try:
        return subprocess.run(cmd + [cosign_image] + list(args), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ValidationError(f"cosign did not finish in {timeout}s")
