import hashlib
import lzma
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

from fabriclib.common.errors import ValidationError
from fabriclib.images.bundle.resolve_packages import resolve_packages

MIRRORS = {"amd64": "http://archive.ubuntu.com/ubuntu", "arm64": "http://ports.ubuntu.com/ubuntu-ports"}
COMPONENTS = ("main", "universe")
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"


def _get(url, timeout=300):
    """Purpose: one file from the Ubuntu archive.
    Inputs:  url — str; timeout — seconds.
    Returns: bytes.
    Fails:   ValidationError naming the URL when the archive refuses; urllib.error.URLError when it cannot be reached.
    Feeds:   fetch_ubuntu."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise ValidationError(f"{url}: the Ubuntu archive answered {e.code} {e.reason}")


def _order(c):
    """Purpose: Debian's ordering of one character in a version's non-digit part (~ first, letters before others).
    Inputs:  c — str of length 0 or 1.
    Returns: int.
    Fails:   never.
    Feeds:   _cmp_part."""
    if c == "~":
        return -1
    if not c:
        return 0
    return ord(c) if c.isalpha() else ord(c) + 256


def _cmp_part(a, b):
    """Purpose: compare an upstream version or revision the way dpkg does.
    Inputs:  a, b — str.
    Returns: negative, 0 or positive.
    Fails:   never.
    Feeds:   _newer."""
    while a or b:
        na, nb = re.match(r"^[^0-9]*", a).group(), re.match(r"^[^0-9]*", b).group()
        for i in range(max(len(na), len(nb))):
            d = _order(na[i] if i < len(na) else "") - _order(nb[i] if i < len(nb) else "")
            if d:
                return d
        a, b = a[len(na):], b[len(nb):]
        da, db = re.match(r"^[0-9]*", a).group(), re.match(r"^[0-9]*", b).group()
        if int(da or 0) != int(db or 0):
            return int(da or 0) - int(db or 0)
        a, b = a[len(da):], b[len(db):]
    return 0


def _newer(a, b):
    """Purpose: whether Debian version a is newer than b (epoch, upstream, revision).
    Inputs:  a, b — version str.
    Returns: bool.
    Fails:   never.
    Feeds:   fetch_ubuntu."""
    def split(v):
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), up, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return ea > eb
    c = _cmp_part(ua, ub)
    return c > 0 if c else _cmp_part(ra, rb) > 0


def _stanzas(text):
    """Purpose: the paragraphs of a Packages file as dicts (continuation lines joined).
    Inputs:  text — str.
    Returns: list of dicts.
    Fails:   never.
    Feeds:   fetch_ubuntu."""
    out = []
    for para in text.split("\n\n"):
        st, key = {}, None
        for line in para.splitlines():
            if line[:1] in (" ", "\t") and key:
                st[key] += "\n" + line
            elif ":" in line:
                key, _, value = line.partition(":")
                st[key] = value.strip()
        if "Package" in st:
            out.append(st)
    return out


def _verified_release(data, keyring):
    """Purpose: an InRelease file's signed text, only once its signature checks against Ubuntu's archive keys.
    Inputs:  data — bytes, the InRelease file; keyring — path of the Ubuntu archive keyring.
    Returns: str, the signed content.
    Fails:   ValidationError when the keyring is missing or gpgv refuses the signature.
    Feeds:   fetch_ubuntu."""
    if not os.path.exists(keyring):
        raise ValidationError(f"{keyring} is missing: the Ubuntu archive's signatures cannot be checked here "
                              "(install ubuntu-keyring)")
    with tempfile.NamedTemporaryFile() as f:
        f.write(data)
        f.flush()
        res = subprocess.run(["gpgv", "--keyring", keyring, "--output", "-", f.name], capture_output=True,
                             timeout=60)
    if res.returncode != 0:
        raise ValidationError("the Ubuntu archive's InRelease signature does not verify: "
                              + res.stderr.decode(errors="replace").strip()[-200:])
    return res.stdout.decode()


def fetch_ubuntu(codename, arch, wanted, dest, mirror=None, keyring=KEYRING, log=print):
    """Purpose: the Ubuntu packages an offline bundle carries for one release and architecture (decision 2.1.14.16,
             manual 1.14.4.10), laid out as a part of the Ubuntu archive that apt on the offline host checks itself:
             each suite's signed InRelease and its components' Packages.xz exactly as Ubuntu publishes them, and
             the .deb files `wanted` needs (resolve_packages) under their pool paths. Here each InRelease is checked
             against Ubuntu's archive keys, each Packages.xz against its InRelease and each .deb against its index.
    Inputs:  codename — "noble" etc.; arch — "amd64" | "arm64"; wanted — package names; dest — folder to write the
             tree in (it becomes the bundle's ubuntu/); mirror — the archive's base URL (default: Ubuntu's own for
             that architecture); keyring — Ubuntu's archive keyring; log — progress printer.
    Returns: dict {"suites": [...], "components": [...], "packages": [names], "files": [paths under dest],
             "size": bytes of the .deb files}.
    Fails:   ValidationError: a signature, index or package that does not check; a package nothing provides; the
             archive refusing. urllib.error.URLError when it cannot be reached; OSError.
    Feeds:   export_bundle."""
    base = mirror or MIRRORS[arch]
    suites = [codename, f"{codename}-updates", f"{codename}-security"]
    files, index = [], {}
    for suite in suites:
        raw = _get(f"{base}/dists/{suite}/InRelease")
        signed = _verified_release(raw, keyring)
        sums = dict((m.group(3), m.group(1)) for m in re.finditer(r"^ ([0-9a-f]{64})\s+(\d+)\s+(\S+)$",
                                                                   signed.split("SHA256:", 1)[-1], re.M))
        rel = f"dists/{suite}/InRelease"
        os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(dest, rel), "wb") as f:
            f.write(raw)
        files.append(rel)
        for comp in COMPONENTS:
            name = f"{comp}/binary-{arch}/Packages.xz"
            data = _get(f"{base}/dists/{suite}/{name}")
            if hashlib.sha256(data).hexdigest() != sums.get(name):
                raise ValidationError(f"{suite}/{name} does not match its signed hash")
            rel = f"dists/{suite}/{name}"
            os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(dest, rel), "wb") as f:
                f.write(data)
            files.append(rel)
            for st in _stanzas(lzma.decompress(data).decode(errors="replace")):
                have = index.get(st["Package"])
                if have is None or _newer(st["Version"], have["Version"]):
                    index[st["Package"]] = st
    chosen = resolve_packages(index, wanted)
    log(f"Ubuntu {codename} {arch}: {len(chosen)} packages")
    size = 0
    for st in chosen:
        data = _get(f"{base}/{st['Filename']}")
        if hashlib.sha256(data).hexdigest() != st.get("SHA256"):
            raise ValidationError(f"{st['Filename']} does not match the archive's index")
        os.makedirs(os.path.join(dest, os.path.dirname(st["Filename"])), exist_ok=True)
        with open(os.path.join(dest, st["Filename"]), "wb") as f:
            f.write(data)
        files.append(st["Filename"])
        size += len(data)
    return {"suites": suites, "components": list(COMPONENTS), "packages": [st["Package"] for st in chosen],
            "files": files, "size": size}
