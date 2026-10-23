import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

import yaml

from fabriclib.common.errors import ValidationError

REPOSITORY = "apt-repository.yaml"


def _get(url):
    """Purpose: one file over HTTPS.
    Inputs:  url — str.
    Returns: bytes.
    Fails:   ValidationError naming the URL when it is refused (404: no such release); urllib.error.URLError.
    Feeds:   fetch_fabric_deb."""
    try:
        with urllib.request.urlopen(url, timeout=300) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise ValidationError(f"{url}: answered {e.code} {e.reason}")


def _gpg(args, work):
    """Purpose: run gpg with a home of its own (nothing of the user's keyrings is read or changed).
    Inputs:  args — list of str; work — the temporary home.
    Returns: subprocess.CompletedProcess (bytes).
    Fails:   ValidationError without gpg.
    Feeds:   fetch_fabric_deb."""
    try:
        return subprocess.run(["gpg", "--homedir", work, "--batch", *args], capture_output=True, timeout=60)
    except FileNotFoundError:
        raise ValidationError("gpg is needed to check fabric's apt repository (install gnupg)")


def fetch_fabric_deb(lock_dir, version, dest):
    """Purpose: the released .deb of this fabric version for an offline bundle (decision 2.1.14.17): the GitHub
             Release asset, checked against the SHA256 that fabric's signed apt repository lists for it — the
             repository's InRelease verified with its public key, whose fingerprint the package pins
             (config/apt-repository.yaml).
    Inputs:  lock_dir — the folder of apt-repository.yaml (beside the lock); version — "0.13.0"; dest — the file to
             write.
    Returns: dict {"file": dest, "version", "sha256", "size"}.
    Fails:   ValidationError: no such release or no such version in the repository; a public key with another
             fingerprint; an InRelease or Packages that does not verify; an asset whose hash is not the listed one
             (dest is not kept); gpg missing. urllib.error.URLError when GitHub cannot be reached.
    Feeds:   export_bundle."""
    with open(os.path.join(lock_dir, REPOSITORY)) as f:
        repo = yaml.safe_load(f)
    work = tempfile.mkdtemp(prefix="fabric-apt-")
    try:
        os.chmod(work, 0o700)
        key = os.path.join(work, "public.key")
        with open(key, "wb") as f:
            f.write(_get(f"{repo['url']}/public.key"))
        shown = _gpg(["--show-keys", "--with-colons", key], work).stdout.decode()
        fprs = re.findall(r"^fpr:+([0-9A-F]{40}):", shown, re.M)
        if not fprs or fprs[0] != repo["fingerprint"]:
            raise ValidationError(f"fabric's apt repository's key is {fprs[:1] or 'unreadable'}, not the pinned "
                                  f"{repo['fingerprint']}: not trusted")
        ring = os.path.join(work, "fabric.gpg")
        _gpg(["--output", ring, "--dearmor", key], work)
        release = os.path.join(work, "InRelease")
        with open(release, "wb") as f:
            f.write(_get(f"{repo['url']}/dists/{repo['suite']}/InRelease"))
        res = subprocess.run(["gpgv", "--keyring", ring, "--output", "-", release], capture_output=True, timeout=60)
        if res.returncode != 0:
            raise ValidationError("fabric's apt repository's InRelease does not verify: "
                                  + res.stderr.decode(errors="replace").strip()[-200:])
        signed = res.stdout.decode()
        name = "main/binary-amd64/Packages"
        sums = dict((m.group(2), m.group(1)) for m in re.finditer(r"^ ([0-9a-f]{64})\s+\d+\s+(\S+)$",
                                                                  signed.split("SHA256:", 1)[-1], re.M))
        packages = _get(f"{repo['url']}/dists/{repo['suite']}/{name}")
        if hashlib.sha256(packages).hexdigest() != sums.get(name):
            raise ValidationError(f"fabric's apt repository's {name} does not match its signed hash")
        want = None
        for para in packages.decode().split("\n\n"):
            st = dict(line.split(": ", 1) for line in para.splitlines() if ": " in line and line[:1] != " ")
            if st.get("Package") == "fabricctl" and st.get("Version") == version:
                want = st.get("SHA256")
        if not want:
            raise ValidationError(f"fabric {version} is not in the apt repository's {repo['suite']} suite: only a "
                                  "released version can be bundled (or give --deb with the file)")
        data = _get(f"{repo['releases']}/v{version}/fabricctl_{version}_all.deb")
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            raise ValidationError(f"the v{version} release's .deb ({got[:12]}…) is not the one the signed apt "
                                  f"repository lists ({want[:12]}…)")
        with open(dest, "wb") as f:
            f.write(data)
        return {"file": dest, "version": version, "sha256": got, "size": len(data)}
    finally:
        shutil.rmtree(work, ignore_errors=True)
