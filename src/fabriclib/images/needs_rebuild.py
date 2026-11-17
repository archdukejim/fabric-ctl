import yaml

from fabriclib.images.built_from import built_from


def needs_rebuild(compose_file):
    """Purpose: whether a compose file's locally built image must be rebuilt: missing, built FROM another
             base than its BASE_IMAGE build arg, (Step-CA) in another GO_IMAGE than its org.fabric.go label, (Kea)
             built with another pinned KEA_VERSION, from older build files (a BUILD_REV build arg against the
             org.fabric.rev label), or built for other
             service account ids (a *_UID/*_GID build arg against the org.fabric.ids label) or other services'
             groups (a *_GID build arg without its *_UID against the org.fabric.groups label).
    Inputs:  compose_file — str, path to a rendered docker-compose.yml. Asks Docker via built_from.
    Returns: bool; False when no service has a build section with BASE_IMAGE, GO_IMAGE, KEA_VERSION, BUILD_REV or
             *_UID.
    Fails:   OSError if the file cannot be read; yaml.YAMLError on invalid YAML; AttributeError if a service's
             `build` is a plain string rather than a mapping.
    Feeds:   deploy/install_service_units (decides whether to run `docker compose build`)."""
    with open(compose_file) as f:
        services = (yaml.safe_load(f) or {}).get("services") or {}
    for svc in services.values():
        args = (svc.get("build") or {}).get("args") or {}
        base = args.get("BASE_IMAGE")
        if base and built_from(svc.get("image", "")) != base:
            return True
        # the image built in a pinned toolchain (Step-CA's certificate reader, GO_IMAGE): another one, or none yet
        if args.get("GO_IMAGE") and built_from(svc.get("image", ""), "org.fabric.go") != args["GO_IMAGE"]:
            return True
        # a pinned upstream package (e.g. KEA_VERSION) changed: its label differs
        if args.get("KEA_VERSION") and built_from(svc.get("image", ""), "org.fabric.kea") != args["KEA_VERSION"]:
            return True
        # the image's own build files changed (their BUILD_REV is bumped): its label differs
        if args.get("BUILD_REV") and built_from(svc.get("image", ""), "org.fabric.rev") != str(args["BUILD_REV"]):
            return True
        # the service account's ids are baked into the image (its /etc/passwd): a changed uid/gid rebuilds
        for key in [k for k in args if k.endswith("_UID")]:
            ids = f"{args[key]}:{args.get(key[:-4] + '_GID', '')}"
            if built_from(svc.get("image", ""), "org.fabric.ids") != ids:
                return True
        # other services' groups baked in (a *_GID with no *_UID, e.g. the DC's BIND_GID): org.fabric.groups
        groups = sorted(k for k in args if k.endswith("_GID") and k[:-4] + "_UID" not in args)
        wanted = ",".join(f"{k}={args[k]}" for k in groups)
        if groups and built_from(svc.get("image", ""), "org.fabric.groups") != wanted:
            return True
    return False
