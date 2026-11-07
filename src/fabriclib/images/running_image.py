import subprocess

from fabriclib.images.built_from import built_from


def running_images(services):
    """Purpose: what several pulled services' containers run, in one `docker inspect`.
    Inputs:  services — SERVICES entries.
    Returns: {container: the image its container was created from}; a missing container is absent.
    Fails:   FileNotFoundError if docker is missing.
    Feeds:   image_status."""
    names = [s["container"] for s in services if not s["build"]]
    if not names:
        return {}
    res = subprocess.run(["docker", "inspect", "-f", "{{.Name}} {{.Config.Image}}", *names],
                         capture_output=True, text=True)
    return {a.lstrip("/"): b for a, _, b in (ln.partition(" ") for ln in res.stdout.splitlines()) if b}


def running_image(service):
    """Purpose: what a service runs now.
    Inputs:  service — a SERVICES entry. For a local build asks the image's base label; otherwise `docker
             inspect` of its container.
    Returns: str ref: the image its container was created from, or for a local build the base it was built
             FROM; None if the container or local image does not exist (or the image has no base label).
    Fails:   FileNotFoundError if docker is missing for a pulled image (local builds return None instead).
    Feeds:   image_status."""
    if service["build"]:
        return built_from(service["build"]) or None
    res = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", service["container"]],
                         capture_output=True, text=True)
    return res.stdout.strip() if res.returncode == 0 else None
