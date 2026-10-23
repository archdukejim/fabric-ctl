import hashlib
import os
import shutil

from fabriclib.common.errors import ValidationError
from fabriclib.consent.plan_member import MEMBER_PACKAGES, RENEW_PACKAGE
from fabriclib.consent.plan_packages import DOCKER_PACKAGES, HOST_PACKAGES
from fabriclib.images.bundle.deb_control import deb_control
from fabriclib.images.bundle.dependency_names import dependency_names
from fabriclib.images.bundle.fetch_fabric_deb import fetch_fabric_deb
from fabriclib.images.bundle.fetch_ubuntu import fetch_ubuntu
from fabriclib.images.bundle.ubuntu_release import ubuntu_release


def export_packages(lock_dir, version, arch, work, ubuntu=None, deb=None, log=print):
    """Purpose: the packages part of an offline bundle (decisions 2.1.14.16, 2.1.14.17; manual 1.14.4.10): fabric's
             .deb — the release's, checked against the signed apt repository, or a file given with --deb (a
             relaxation: not checked) — and, for one Ubuntu release, everything it and setup install (the host
             packages, Docker, the domain member's), as a part of the Ubuntu archive apt checks on the host.
    Inputs:  lock_dir — the package's folder (VERSION, apt-repository.yaml); version — this fabric's version;
             arch — "amd64" | "arm64"; work — an empty folder to write in; ubuntu — "24.04" style or None (this
             machine's); deb — a .deb file to carry instead of the release's, or None; log — progress printer.
    Returns: dict {"deb": {"file", "version", "sha256", "checked": bool}, "ubuntu": {"release", "codename",
             "suites", "components", "packages"}, "members": [(path in the bundle, path in work)]}.
    Fails:   ValidationError: an Ubuntu release fabric's hosts do not run, or none named on a machine that is not
             Ubuntu; a --deb that is not fabricctl or not this version; everything fetch_fabric_deb and fetch_ubuntu
             refuse. urllib.error.URLError; OSError.
    Feeds:   export_bundle."""
    release, codename = ubuntu_release(ubuntu)
    os.makedirs(os.path.join(work, "deb"), exist_ok=True)
    if deb:
        fields = deb_control(deb)
        if fields.get("Package") != "fabricctl" or fields.get("Version", "").split("~")[0] != version:
            raise ValidationError(f"{deb} is {fields.get('Package')} {fields.get('Version')}, not fabricctl {version}")
        name = f"fabricctl_{fields['Version']}_all.deb"
        shutil.copy(deb, os.path.join(work, "deb", name))
        with open(deb, "rb") as f:
            got = {"version": fields["Version"], "sha256": hashlib.sha256(f.read()).hexdigest(), "checked": False}
        log(f"fabric's .deb: {deb} (--deb: not checked against the apt repository)")
    else:
        name = f"fabricctl_{version}_all.deb"
        got = dict(fetch_fabric_deb(lock_dir, version, os.path.join(work, "deb", name)), checked=True)
        got.pop("size", None)
        log(f"fabric's .deb: the v{version} release, checked against the signed apt repository")
    got["file"] = f"deb/{name}"
    depends = [alts[0] for alts in dependency_names(deb_control(os.path.join(work, got["file"])).get("Depends"))]
    wanted = sorted(set(depends + HOST_PACKAGES + DOCKER_PACKAGES + MEMBER_PACKAGES + [RENEW_PACKAGE]))
    tree = fetch_ubuntu(codename, arch, wanted, os.path.join(work, "ubuntu"), log=log)
    members = [(got["file"], os.path.join(work, got["file"]))]
    members += [(f"ubuntu/{rel}", os.path.join(work, "ubuntu", rel)) for rel in tree["files"]]
    return {"deb": got, "ubuntu": {"release": release, "codename": codename, "suites": tree["suites"],
                                   "components": tree["components"], "packages": tree["packages"]},
            "members": members}
