from fabriclib.common.read_images_lock import read_images_lock
from fabriclib.common.read_published_lock import read_published_lock


def bundle_images(lock_dir):
    """Purpose: what an offline bundle of this fabric carries (decision 2.1.14.14): every image of the lock, the
             upstream ones under their own names and fabric's published ones as "fabric/<name>".
    Inputs:  lock_dir — str, the folder holding images.lock.yaml and VERSION (the package's fabric/, or a
             checkout's config/).
    Returns: dict {key: {"repo", "tag", "digest", "ref", "file": "images/<key with - for />.tar", "published": bool,
             "pending": str or ""}}, keys sorted; a published image not published yet has an empty digest and its
             `pending` reason.
    Fails:   what read_images_lock and read_published_lock raise (YAML, a malformed entry, OSError).
    Feeds:   export_bundle, check_bundle."""
    out = {}
    for name, e in read_images_lock(lock_dir).items():
        out[name] = {"repo": e["repo"], "tag": str(e["tag"]), "digest": e["digest"], "ref": e["ref"],
                     "published": False, "pending": ""}
    for name, e in (read_published_lock(lock_dir).get("images") or {}).items():
        out[f"fabric/{name}"] = {"repo": e["repo"], "tag": str(e.get("tag") or ""), "digest": e.get("digest") or "",
                                 "ref": e["ref"], "published": True,
                                 "pending": "" if e.get("digest") else (e.get("pending") or "not published")}
    for key, e in out.items():
        e["file"] = f"images/{key.replace('/', '-')}.tar"
    return dict(sorted(out.items()))
