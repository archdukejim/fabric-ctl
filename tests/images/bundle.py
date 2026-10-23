"""Offline install bundles (decision 2.1.14.14, manual 1.14.4), against the real registries, real keyless signatures
and the pinned cosign. Needs Docker, root and network access (the export is online). Run by tests/images/run.sh.
Loading the images, with no network, is tests/images/offline.sh's.

A small lock (cosign, nginx and fabric's published bind9) keeps it to about 350 MB, with this checkout's .deb
(packaging/deb/build-deb.sh) given as --deb, and this machine's Ubuntu release's packages:
- `images export` writes one bundle: fabric's .deb, a part of the Ubuntu archive, each image its own OCI layout, the
  published one's signature, a manifest with every file's sha256; the bundle checks as a whole and its signature
  offline, against the trusted root the package ships (config/sigstore-trusted-root.json), which is Sigstore's
  current one
- packages (2.1.14.16, 2.1.14.17, 2.1.14.23): the bundle's packages unpack as a local apt source real apt reads,
  checks and resolves the domain member's packages and Docker's (unless docker-ce runs there) from (simulated:
  nothing is installed here); the release's .deb is fetched and checked against the signed apt repository (0.7.2); refused: a version not released,
  an apt repository key with another fingerprint, a --deb of another version, an Ubuntu release fabric's hosts do
  not run, a bundle for another Ubuntu release; a --deb bundle shows as relaxed
- refused, with why and nothing written: an unknown architecture, a file that exists, an image the lock has not
  published (the repository's own lock, and a small one), not enough space; the command's usage errors
- with --allow-unpublished (2.1.14.21) the unpublished image is left out and recorded; the import's `relaxed:` line
  and the relaxed-settings row say so
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
from fabriclib.images.bundle.describe_import import describe_import  # noqa: E402
from fabriclib.images.bundle.export_bundle import export_bundle  # noqa: E402
from fabriclib.images.bundle.extract_bundle_apt import extract_bundle_apt  # noqa: E402
from fabriclib.images.bundle.fetch_fabric_deb import fetch_fabric_deb  # noqa: E402
from fabriclib.images.bundle.host_arch import host_arch  # noqa: E402
from fabriclib.images.bundle.import_bundle import import_bundle  # noqa: E402
from fabriclib.images.bundle.ubuntu_release import ubuntu_release  # noqa: E402
from fabriclib.images.bundle.verify_offline import verify_offline  # noqa: E402
from fabriclib.images.run_images_command import run_images_command  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.system.relaxed_settings import relaxed_settings  # noqa: E402

PASS = FAIL = 0
ARCH = host_arch()
OTHER = "arm64" if ARCH == "amd64" else "amd64"
FULL = yaml.safe_load(open(os.path.join(REPO, "config", "images.lock.yaml")))
COSIGN = read_images_lock(os.path.join(REPO, "config"))["cosign"]["ref"]
RELEASE = ubuntu_release()[0]
RELEASED = "0.7.2"                    # a version in the signed apt repository's stable suite


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
    shutil.copy(os.path.join(REPO, "config", "apt-repository.yaml"), folder)
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
    version = open(os.path.join(lock, "VERSION")).read().strip()
    DEB = subprocess.run(["bash", os.path.join(REPO, "packaging", "deb", "build-deb.sh")], capture_output=True,
                         text=True, env=dict(os.environ, OUT=os.path.join(work, "dist")), check=True).stdout.strip()
    bundle = os.path.join(work, "fabric.tar")
    # covers: cli:images.export +
    manifest = export_bundle(lock, ARCH, bundle, log=QUIET, deb=DEB)
    with tarfile.open(bundle) as tar:
        names = sorted(m.name for m in tar.getmembers())
    deb_name = f"deb/fabricctl_{manifest['deb']['version']}_all.deb"   # a checkout's build: <version>~git…
    check("images export writes one bundle: fabric's .deb, the Ubuntu packages, an OCI layout per image, the published "
          "image's signature and the manifest (no trusted root: the package ships it)",
          [n for n in names if not n.startswith("ubuntu/")]
          == [deb_name, "images/cosign.tar", "images/fabric-bind9.tar", "images/nginx.tar", "manifest.json",
              "signatures/fabric-bind9.json"]
          and f"ubuntu/dists/{manifest['ubuntu']['codename']}/InRelease" in names
          and any(n.startswith("ubuntu/pool/") and "/docker.io_" in n for n in names), names[:8])
    check("the manifest names the fabric version, the architecture, the Ubuntu release, every image by the lock's "
          "digest and every file's sha256",
          manifest["fabric"] == version and manifest["arch"] == ARCH and manifest["ubuntu"]["release"] == RELEASE
          and manifest["images"]["nginx"]["digest"] == FULL["images"]["nginx"]["digest"]
          and set(manifest["files"]) == set(names) - {"manifest.json"}
          and all(len(f["sha256"]) == 64 for f in manifest["files"].values()))
    check("a --deb export records the .deb as not checked (2.1.14.23)",
          manifest["deb"]["file"] == deb_name and manifest["deb"]["checked"] is False
          and manifest["deb"]["version"].split("~")[0] == version, manifest["deb"])
    lines = describe_import({"loaded": [], "present": [], "verified": [], "unchecked": [], "left_out": {},
                             "deb_unchecked": version})
    check("the import shows a --deb bundle as a relaxation", any(ln.startswith("relaxed:") and "--deb" in ln
                                                                 for ln in lines), lines)
    rec = os.path.join(work, "bundle-deb.json")
    with open(rec, "w") as f:
        json.dump({"left_out": {}, "deb_unchecked": version}, f)
    check("status and doctor list a --deb bundle among the relaxed settings",
          any("--deb" in r["setting"] for r in relaxed_settings({}, config_dir=work, bundle_record=rec)))
    # the web UI's Overview: fabric-agent (root) answers GET /v1/relaxed-settings from the same record (2.1.14.25)
    import agent.get_route as agent_route
    import fabriclib.system.relaxed_settings as relaxed_module
    saved = relaxed_module.BUNDLE_RECORD, agent_route.load_vars
    try:
        relaxed_module.BUNDLE_RECORD, agent_route.load_vars = rec, dict
        rows = agent_route.get_route(["relaxed-settings"])
    finally:
        relaxed_module.BUNDLE_RECORD, agent_route.load_vars = saved
    check("fabric-agent's relaxed-settings route, which the web UI's Overview shows, lists it too",
          any("--deb" in r["setting"] for r in rows), rows)

    # the packages as a local apt source (2.1.14.16): real apt reads, checks and resolves from it, simulating only
    apt_dir = tempfile.mkdtemp(prefix="bundles-apt-", dir="/var/tmp")
    os.chmod(apt_dir, 0o755)
    try:
        source = extract_bundle_apt(bundle, lock, apt_dir)
        apt_env = dict(os.environ, APT_CONFIG=source["config"])
        upd = subprocess.run(["apt-get", "-q", "update"], capture_output=True, text=True, env=apt_env)
        # docker.io too, unless this machine runs Docker's own docker-ce, which it conflicts with (offline.sh
        # installs it on a bare host)
        docker_ce = subprocess.run(["dpkg", "-s", "docker-ce"], capture_output=True).returncode == 0
        wanted = ["sssd-ad", "realmd", "adcli"] + ([] if docker_ce else ["docker.io", "docker-compose-v2"])
        sim = subprocess.run(["apt-get", "-s", "--no-install-recommends", "install", *wanted], capture_output=True,
                             text=True, env=apt_env)
        check("the bundle's packages unpack as a local apt source: apt checks its signed InRelease and resolves "
              "the domain member's packages, and Docker's unless docker-ce runs here, from it alone",
              upd.returncode == 0 and not upd.stderr.strip() and sim.returncode == 0
              and os.path.exists(source["deb"]), (upd.stdout + upd.stderr + sim.stderr)[-400:])
    finally:
        shutil.rmtree(apt_dir, ignore_errors=True)
    why = refusal(check_bundle, bundle, lock, ARCH, log=QUIET, release="22.04" if RELEASE != "22.04" else "24.04")
    check("a bundle for another Ubuntu release is refused, naming both", "packages are for Ubuntu" in why, why)

    released = os.path.join(work, "released.deb")
    got = fetch_fabric_deb(lock, RELEASED, released)
    check("the release's .deb is fetched from its GitHub Release and matches the signed apt repository's hash",
          got["version"] == RELEASED and len(got["sha256"]) == 64 and os.path.getsize(released) == got["size"], got)
    why = refusal(fetch_fabric_deb, lock, "0.0.1", os.path.join(work, "none.deb"))
    check("a version the apt repository does not list is refused, pointing to --deb",
          "not in the apt repository" in why and "--deb" in why and not os.path.exists(os.path.join(work, "none.deb")),
          why)
    forged = make_lock(os.path.join(work, "lock-forged"))
    with open(os.path.join(forged, "apt-repository.yaml")) as f:
        repo_cfg = yaml.safe_load(f)
    repo_cfg["fingerprint"] = "0" * 40
    with open(os.path.join(forged, "apt-repository.yaml"), "w") as f:
        yaml.safe_dump(repo_cfg, f)
    why = refusal(fetch_fabric_deb, forged, RELEASED, os.path.join(work, "forged.deb"))
    check("an apt repository whose key is not the pinned fingerprint is not trusted", "not trusted" in why, why)
    why = refusal(export_bundle, lock, ARCH, os.path.join(work, "wrong.tar"), log=QUIET, deb=released)
    check("export refuses a --deb of another version, writing nothing",
          f"not fabricctl {version}" in why and not os.path.exists(os.path.join(work, "wrong.tar")), why)
    why = refusal(export_bundle, lock, ARCH, os.path.join(work, "focal.tar"), log=QUIET, ubuntu="20.04")
    check("export refuses an Ubuntu release fabric's hosts do not run", "not a release fabric's hosts run" in why, why)
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
    code, text = run_cli(["export", "--arch", ARCH, "-o", os.path.join(work, "u.tar"), "--ubuntu"])
    check("export with --ubuntu and no release is a usage error", code == 2, text[-200:])
    code, text = run_cli(["export", "--arch", ARCH, "--arch", OTHER, "-o", os.path.join(work, "u.tar")])
    check("export with an option given twice is a usage error", code == 2, text[-200:])

    # an unpublished image (2.1.14.21): refused by default, left out with --allow-unpublished, and shown as relaxed
    def unpublish_bind9(lk):
        lk["published"]["images"]["bind9"].update(digest="", tag="", pending="a test: not published")
    held = make_lock(os.path.join(work, "lock-pending"), change=unpublish_bind9)
    why = refusal(export_bundle, held, ARCH, os.path.join(work, "held.tar"), log=QUIET)
    check("export refuses an unpublished image by default, naming it, why and --allow-unpublished",
          "fabric/bind9 (a test: not published)" in why and "--allow-unpublished" in why, why)
    left = export_bundle(held, ARCH, os.path.join(work, "held.tar"), log=QUIET, allow_unpublished=True, deb=DEB)
    check("with --allow-unpublished the export leaves it out and the manifest records it with why",
          left["left_out"] == {"fabric/bind9": "a test: not published"} and "fabric/bind9" not in left["images"]
          and sorted(check_bundle(os.path.join(work, "held.tar"), held, ARCH, log=QUIET)["indexes"])
          == ["cosign", "nginx"])
    lines = describe_import({"loaded": [], "present": [], "verified": [], "unchecked": [],
                             "left_out": left["left_out"], "deb_unchecked": None})
    check("the import says so as a relaxation", any(ln.startswith("relaxed:") and "fabric/bind9" in ln
                                                    for ln in lines), lines)
    rec = os.path.join(work, "bundle.json")
    with open(rec, "w") as f:
        json.dump({"left_out": left["left_out"]}, f)
    rows = relaxed_settings({}, config_dir=work, bundle_record=rec)
    check("status and doctor list it among the relaxed settings while the record is there",
          any("--allow-unpublished" in r["setting"] and "fabric/bind9" in r["effect"] for r in rows)
          and not any("--allow-unpublished" in r["setting"]
                      for r in relaxed_settings({}, config_dir=work, bundle_record=rec + ".none")), rows)
    os.makedirs(tiny)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=8m", "bundles-test", tiny], check=True)
    why = refusal(export_bundle, lock, ARCH, os.path.join(tiny, "b.tar"), log=QUIET, deb=DEB)
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
