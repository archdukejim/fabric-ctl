import os
import sys
import urllib.error

from fabriclib.common.errors import ValidationError
from fabriclib.common.lock_dir import lock_dir
from fabriclib.common.paths import FABRIC_DIR
from fabriclib.images.bundle.describe_import import describe_import
from fabriclib.images.bundle.export_bundle import export_bundle
from fabriclib.images.bundle.import_bundle import import_bundle
from fabriclib.images.image_status import image_status
from fabriclib.images.prune_images import prune_images
from fabriclib.images.rollback_image import rollback_image
from fabriclib.images.update_images import update_images

USAGE = """usage: fabricctl images status                  each service: running, validated, update available?
       fabricctl images update <service…>|--all [--force]
                                               move to the validated images (compose down/up per service,
                                               health-gated, rolled back on failure); --force: also images
                                               the admin set in vars.yaml
       fabricctl images rollback <service>     back to the image before the last update
       fabricctl images prune                  remove old images of fabric's repositories (not in use,
                                               not the rollback image)
       fabricctl images export --arch amd64|arm64 -o <file> [--ubuntu <release>] [--deb <file>]
                               [--allow-unpublished]
                                               an offline install bundle of this release (online): fabric's
                                               .deb and the Ubuntu packages for one release (--ubuntu, e.g.
                                               24.04; default this machine's), every image of the lock by
                                               digest, their signatures, a manifest; --deb: carry this .deb
                                               instead of the release's (a relaxation: not checked);
                                               --allow-unpublished: leave out images not published (a
                                               relaxation: the host must build them, with the internet)
       fabricctl images import <bundle>        check a bundle offline (version, architecture, digests,
                                               hashes, signatures), then load its images; fetches nothing"""

EXPORT_VALUES = ("--arch", "-o", "--ubuntu", "--deb")


def _export_options(args):
    """Purpose: `images export`'s options, each given once with its value.
    Inputs:  args — list of str after "export".
    Returns: dict {"--arch", "-o", "--ubuntu", "--deb": str or None, "--allow-unpublished": bool}, or None for a
             usage error (an unknown or repeated option, a value missing, --arch or -o absent).
    Fails:   never.
    Feeds:   run_images_command (export)."""
    got, rest = {"--allow-unpublished": False}, list(args)
    while rest:
        name = rest.pop(0)
        if name == "--allow-unpublished" and not got[name]:
            got[name] = True
        elif name in EXPORT_VALUES and name not in got and rest and not rest[0].startswith("-"):
            got[name] = rest.pop(0)
        else:
            return None
    return got if "--arch" in got and "-o" in got else None


def _short(ref):
    """Purpose: a short display form of an image ref.
    Inputs:  ref — str "repo:tag@sha256:…" or None/"".
    Returns: str "repo:tag@<12 hex chars of the digest>", the ref unchanged without a digest, or "—" when empty.
    Fails:   never.
    Feeds:   run_images_command."""
    if not ref:
        return "—"
    name, _, digest = ref.partition("@")
    return f"{name}@{digest[7:19]}" if digest else name


def _prune(ctx):
    """Purpose: after an update, remove old images unless the admin turned it off.
    Inputs:  ctx — SetupContext; reads vars image_prune (default true).
    Returns: None; prints how many images were cleaned up.
    Fails:   whatever prune_images raises.
    Feeds:   run_images_command (update)."""
    if ctx.vars.get("image_prune", True):
        removed = prune_images(ctx)
        print(f"cleaned up {len(removed)} old image(s)" if removed else "no old images to clean up")


def run_images_command(ctx, argv):
    """Purpose: route `fabricctl images status|update|rollback|prune` (design 2.1.14.3) and `export|import`
             (offline bundles, 2.1.14.14) and print the results. Nothing here runs on its own; applying is these
             commands. export and import use the lock of the fabric this code belongs to (the package's).
    Inputs:  ctx — SetupContext with state loaded; argv — list of str after "images" (empty = status).
    Returns: exit status int: 0 done, 1 ValidationError (printed to stderr), 2 usage error (usage printed).
    Fails:   ValidationError, and a registry the export cannot reach (URLError), are caught and become exit 1;
             other errors (Docker, YAML, SetupError from deploy) propagate to the caller.
    Feeds:   cli.py (`fabricctl images`)."""
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        if cmd == "status" and not args:
            rows = image_status(ctx)
            for r in rows:
                line = f"{r['service']:<9} {r['state']:<24} runs {_short(r['running'])}"
                if r["state"] in ("update available", "held (set by the admin)"):
                    line += f"  →  {_short(r['validated'])}"
                print(line)
            n = sum(r["state"] == "update available" for r in rows)
            print(f"\n{n} update(s) available: sudo fabricctl images update --all" if n else "\nall images current")
            return 0
        if cmd == "update" and args:
            names = None if "--all" in args else [a for a in args if not a.startswith("--")]
            done = update_images(ctx, names, force="--force" in args)
            for var, target, services in done:
                print(f"updated {', '.join(services)} → {_short(target)}")
            if not done:
                print("nothing to update")
            else:
                _prune(ctx)
            return 0
        if cmd == "rollback" and len(args) == 1:
            moved = rollback_image(ctx, args[0])
            print(f"rolled back {', '.join(moved)}" if moved else "already on the previous image")
            return 0
        opts = _export_options(args) if cmd == "export" else None
        if opts:
            out = opts["-o"]
            manifest = export_bundle(lock_dir(os.path.join(FABRIC_DIR, "jinja")), opts["--arch"], out,
                                     log=lambda line: print(line, flush=True),
                                     allow_unpublished=opts["--allow-unpublished"], ubuntu=opts.get("--ubuntu"),
                                     deb=opts.get("--deb"))
            print(f"bundle for fabric {manifest['fabric']} ({manifest['arch']}, Ubuntu "
                  f"{manifest['ubuntu']['release']}), {len(manifest['images'])} images, "
                  f"{len(manifest['ubuntu']['packages'])} packages: {out}")
            if not manifest["deb"]["checked"]:
                print(f"relaxed: fabricctl {manifest['deb']['version']} is the --deb file, not checked against "
                      "fabric's signed apt repository (2.1.14.23)")
            return 0
        if cmd == "import" and len(args) == 1 and not args[0].startswith("-"):
            done = import_bundle(args[0], lock_dir(os.path.join(FABRIC_DIR, "jinja")),
                                 signature_check=ctx.vars.get("image_signature_check", True),
                                 log=lambda line: print(line, flush=True))
            for line in describe_import(done):
                print(line)
            return 0
        if cmd == "prune" and not args:
            removed = prune_images(ctx)
            for r in removed:
                print(f"removed {r}")
            print(f"{len(removed)} old image(s) removed")
            return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:          # export: a registry or Sigstore that cannot be reached
        print(f"error: cannot reach {exc.reason}: the export needs the internet; nothing was written",
              file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
