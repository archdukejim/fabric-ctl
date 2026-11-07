from fabriclib.common.read_images_lock import read_images_lock
from fabriclib.common.read_published_lock import read_published_lock
from fabriclib.images.installed_services import installed_services
from fabriclib.images.running_image import running_image, running_images


def image_status(ctx):
    """Purpose: per installed service, which image it runs, is set to and should run, and its state.
             Read-only.
    Inputs:  ctx — SetupContext with vars loaded and target_dir (the installed fabric holding images.lock.yaml).
             Reads vars `image_*` and `image_pins`, the lock file (images and published) and Docker (via
             running_image).
    Returns: list of dicts in update order: {service, var, running, applied, validated, state}; state is
             "not running", "restart needed" (running differs from vars), "held (set by the admin)" (var in
             image_pins and not the validated ref), "update available", or "current".
    Fails:   errors from read_images_lock (yaml.YAMLError, KeyError) propagate.
    Feeds:   run_images_command (status), update_images.
    Notes:   for local builds "running" is the base the image was built FROM, so it is compared with the base ref."""
    v = ctx.vars
    validated = {e["var"]: e["ref"] for e in read_images_lock(ctx.target_dir).values()}
    # fabric's published images (manual 1.14.3): their var is image_fabric_<name> while a service runs one
    validated.update({e["var"]: e["ref"] for e in (read_published_lock(ctx.target_dir).get("images") or {}).values()
                      if e["ref"]})
    held = set(v.get("image_pins") or [])
    rows = []
    services = installed_services(ctx)
    pulled = running_images(services)
    for s in services:
        running = running_image(s) if s["build"] else pulled.get(s["container"])
        applied, want = v.get(s["var"]), validated.get(s["var"])
        if running is None:
            state = "not running"
        elif running != applied:
            state = "restart needed"
        elif want and applied != want:
            state = "held (set by the admin)" if s["var"] in held else "update available"
        else:
            state = "current"
        rows.append({"service": s["name"], "var": s["var"], "running": running, "applied": applied,
                     "validated": want, "state": state})
    return rows
