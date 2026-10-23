"""Offline install bundles (decision 2.1.14.14, manual 1.14.4), against the real registries, real keyless signatures
and the pinned cosign. Needs Docker, root and network access (the export is online). Run by tests/images/run.sh.
Loading the images, with no network, is tests/images/offline.sh's.

A small lock (cosign, nginx and fabric's published bind9) keeps it to about 200 MB:
- `images export` writes one bundle: each image its own OCI layout, the published one's signature, Sigstore's
  manifest with every file's sha256; the bundle checks as a whole and its signature offline, against the trusted
  root the package ships (config/sigstore-trusted-root.json)
- refused, with why and nothing written: an unknown architecture, a file that exists, an image the lock has not
  published (the repository's own lock), not enough space; the command's usage errors
- check refuses: a bundle for another fabric version or architecture, one lacking an image the lock pins, one
  carrying another digest than the lock's, one cut short, one with a changed byte, a file that is not a bundle
- the offline signature check refuses another signer and another image's signature
- the import refuses a bundle when Docker's store has not the room, before loading anything
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from contextlib import redirect_stderr, redirect_stdout

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.common.read_images_lock import read_images_lock  # noqa: E402
from fabriclib.images.bundle.check_bundle import check_bundle  # noqa: E402
from fabriclib.images.bundle.export_bundle import export_bundle  # noqa: E402
from fabriclib.images.bundle.host_arch import host_arch  # noqa: E402
from fabriclib.images.bundle.import_bundle import import_bundle  # noqa: E402
from fabriclib.images.bundle.verify_offline import verify_offline  # noqa: E402
from fabriclib.images.run_images_command import run_images_command  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402

PASS = FAIL = 0
ARCH = host_arch()
OTHER = "arm64" if ARCH == "amd64" else "amd64"
FULL = yaml.safe_load(open(os.path.join(REPO, "config", "images.lock.yaml")))
COSIGN = read_images_lock(os.path.join(REPO, "config"))["cosign"]["ref"]


def QUIET(line):
    return None


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {name}")
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def refusal(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except ValidationError as e:
        return str(e)
    return ""


def make_lock(folder, upstream=("cosign", "nginx"), published=("bind9",), version=None, change=None, root=True):
    """A lock folder holding a part of the repository's lock (and its VERSION)."""
    os.makedirs(folder, exist_ok=True)
    lock = json.loads(json.dumps(FULL))
    lock["images"] = {k: v for k, v in lock["images"].items() if k in upstream}
    lock["published"]["images"] = {k: v for k, v in lock["published"]["images"].items() if k in published}
    lock.pop("packages", None)
    if change:
        change(lock)
    with open(os.path.join(folder, "images.lock.yaml"), "w") as f:
        yaml.safe_dump(lock, f)
    with open(os.path.join(folder, "VERSION"), "w") as f:
        f.write(version or open(os.path.join(REPO, "config", "VERSION")).read())
    if root:
        shutil.copy(os.path.join(REPO, "config", "sigstore-trusted-root.json"), folder)
    return folder


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = run_images_command(SetupContext(deploy_base=os.path.join(work, "nothing")), argv)
    return code, out.getvalue() + err.getvalue()


work = tempfile.mkdtemp(prefix="bundles-test-", dir="/var/tmp")
tiny = os.path.join(work, "tiny")
try:
    lock = make_lock(os.path.join(work, "lock"))
    bundle = os.path.join(work, "fabric.tar")
    # covers: cli:images.export +
    manifest = export_bundle(lock, ARCH, bundle, log=QUIET)
    with tarfile.open(bundle) as tar:
        names = sorted(m.name for m in tar.getmembers())
    check("images export writes one bundle: an OCI layout per image, the published image's signature and the "
          "manifest (no trusted root: the package ships it)",
          names == ["images/cosign.tar", "images/fabric-bind9.tar", "images/nginx.tar", "manifest.json",
                    "signatures/fabric-bind9.json"], names)
    check("the manifest names the fabric version, the architecture, every image by the lock's digest and every "
          "file's sha256",
          manifest["fabric"] == open(os.path.join(lock, "VERSION")).read().strip() and manifest["arch"] == ARCH
          and manifest["images"]["nginx"]["digest"] == FULL["images"]["nginx"]["digest"]
          and set(manifest["files"]) == set(names) - {"manifest.json"}
          and all(len(f["sha256"]) == 64 for f in manifest["files"].values()))
    checked = check_bundle(bundle, lock, ARCH, log=QUIET)
    check("the bundle checks as a whole: version, architecture, every pinned image's blobs and every hash",
          sorted(checked["indexes"]) == ["cosign", "fabric/bind9", "nginx"])
    with tarfile.open(bundle) as tar:
        sig = tar.extractfile("signatures/fabric-bind9.json").read()
    root = open(os.path.join(REPO, "config", "sigstore-trusted-root.json"), "rb").read()
    pub = FULL["published"]
    bind9 = manifest["images"]["fabric/bind9"]["ref"]
    check("the published image's carried signature verifies with no network, against fabric's signer",
          not refusal(verify_offline, bind9, checked["indexes"]["fabric/bind9"], sig, root, COSIGN,
                      pub["signer"], pub["issuer"]))
    why = refusal(verify_offline, bind9, checked["indexes"]["fabric/bind9"], sig, root, COSIGN,
                  "^https://example\\.com/", pub["issuer"])
    check("offline, a signature by another signer is refused, naming the image", "bind9" in why and "SAN" in why, why)
    why = refusal(verify_offline, "nginx", checked["indexes"]["nginx"], sig, root, COSIGN,
                  pub["signer"], pub["issuer"])
    check("offline, one image's signature does not pass for another's", "does not verify" in why, why)

    # covers: cli:images.export -
    check("export refuses an unknown architecture", "unknown architecture" in refusal(
        export_bundle, lock, "riscv64", os.path.join(work, "x.tar"), log=QUIET))
    check("export refuses to overwrite a file", "exists" in refusal(export_bundle, lock, ARCH, bundle, log=QUIET))
    code, text = run_cli(["export", "--arch", ARCH, "-o", os.path.join(work, "repo.tar")])
    check("export refuses a lock with an image not published yet, naming it and why, writing nothing",
          code == 1 and "not published" in text and "fabric/webui" in text
          and not os.path.exists(os.path.join(work, "repo.tar")), text[-300:])
    code, text = run_cli(["export", "--arch", ARCH])
    check("export without -o is a usage error", code == 2 and "images export --arch" in text, text[-200:])
    os.makedirs(tiny)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=8m", "bundles-test", tiny], check=True)
    why = refusal(export_bundle, lock, ARCH, os.path.join(tiny, "b.tar"), log=QUIET)
    check("export refuses when there is not the space, naming needed and free, writing nothing",
          "not enough space" in why and "MiB" in why and not os.listdir(tiny), why)

    # covers: cli:images.import -
    other = make_lock(os.path.join(work, "lock-other"), version="0.0.1")
    check("a bundle for another fabric version is refused, naming both",
          "for fabric" in refusal(check_bundle, bundle, other, ARCH, log=QUIET))
    check("a bundle for another architecture is refused",
          f"this host is {OTHER}" in refusal(check_bundle, bundle, lock, OTHER, log=QUIET))
    more = make_lock(os.path.join(work, "lock-more"), upstream=("cosign", "nginx", "debian"))
    why = refusal(check_bundle, bundle, more, ARCH, log=QUIET)
    check("a bundle lacking an image the lock pins is refused, naming it", "lacks images" in why and "debian" in why,
          why)
    prev = yaml.safe_load(open(os.path.join(REPO, "tests", "images", "previous.yaml")))
    nginx_prev = prev["previous"]["image_nginx"]["digest"]

    def other_nginx(lk):
        lk["images"]["nginx"]["digest"] = nginx_prev
    moved = make_lock(os.path.join(work, "lock-moved"), change=other_nginx)
    why = refusal(check_bundle, bundle, moved, ARCH, log=QUIET)
    check("a bundle carrying another digest than the lock pins is refused, naming both", "lock pins" in why, why)
    cut = os.path.join(work, "cut.tar")
    with open(bundle, "rb") as src, open(cut, "wb") as dst:
        dst.write(src.read(os.path.getsize(bundle) // 2))
    why = refusal(check_bundle, cut, lock, ARCH, log=QUIET)
    check("a bundle cut short is refused as damaged", "damaged" in why or "lacks" in why, why)
    flipped = os.path.join(work, "flipped.tar")
    shutil.copy(bundle, flipped)
    with tarfile.open(flipped) as tar:
        member = tar.getmember("images/nginx.tar")
    with open(flipped, "r+b") as f:
        f.seek(member.offset_data + member.size // 2)
        byte = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([byte[0] ^ 0xFF]))
    why = refusal(check_bundle, flipped, lock, ARCH, log=QUIET)
    check("a bundle with one changed byte is refused, naming the file", "images/nginx.tar does not match" in why, why)
    junk = os.path.join(work, "junk.tar")
    with open(junk, "wb") as f:
        f.write(os.urandom(4096))
    check("a file that is not a bundle is refused", "not a readable bundle" in refusal(check_bundle, junk, lock, ARCH,
                                                                                         log=QUIET))
    bare = make_lock(os.path.join(work, "lock-noroot"), root=False)
    why = refusal(import_bundle, bundle, bare, cache=os.path.join(work, "v.json"), log=QUIET)
    check("a fabric that ships no trusted root refuses the import (or a classic store does, first)",
          "no Sigstore trusted root" in why or "classic store" in why, why)
    res = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "images", "trusted_root.py"), "--check"],
                         capture_output=True, text=True)
    check("the trusted root the package ships is Sigstore's current one (scripts/images/trusted_root.py --check)",
          res.returncode == 0, (res.stdout + res.stderr)[-300:])
    code, text = run_cli(["import", junk])
    check("images import refuses it too, exit 1 and why", code == 1 and "not a readable bundle" in text, text[-200:])
    code, text = run_cli(["import"])
    check("images import without a bundle is a usage error", code == 2 and "images import <bundle>" in text)
    store = subprocess.run(["docker", "info", "--format", "{{json .DriverStatus}}"], capture_output=True, text=True)
    absent = [e["ref"] for e in manifest["images"].values()
              if subprocess.run(["docker", "image", "inspect", e["ref"]], capture_output=True).returncode != 0]
    if "io.containerd.snapshotter" in store.stdout and absent:
        before = subprocess.run(["docker", "images", "-q", "--no-trunc"], capture_output=True, text=True).stdout
        why = refusal(import_bundle, bundle, lock, cache=os.path.join(work, "v.json"), store=tiny, log=QUIET)
        after = subprocess.run(["docker", "images", "-q", "--no-trunc"], capture_output=True, text=True).stdout
        check("import refuses when Docker's store has not the room, naming needed and free, loading nothing",
              "not enough space" in why and before == after, why)
    else:
        print("SKIP the import's space check here: this machine's Docker is on the classic store, or already has "
              "every image (tests/images/offline.sh checks it)")
finally:
    subprocess.run(["umount", tiny], capture_output=True)
    shutil.rmtree(work, ignore_errors=True)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
