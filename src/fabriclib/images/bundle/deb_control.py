import io
import lzma
import tarfile

from fabriclib.common.errors import ValidationError


def deb_control(path):
    """Purpose: the control fields of a .deb (its Package, Version, Depends, …), read with Python alone (no dpkg on
             the exporting machine needed): the ar archive's control.tar.xz or control.tar.gz.
    Inputs:  path — str, a .deb file.
    Returns: dict {field: value}.
    Fails:   ValidationError when the file is not a .deb this can read (another compression than xz or gz);
             OSError.
    Feeds:   export_bundle."""
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise ValidationError(f"{path} is not a .deb")
        while True:
            head = f.read(60)
            if len(head) < 60:
                raise ValidationError(f"{path} has no control archive")
            name, size = head[:16].decode().strip().rstrip("/"), int(head[48:58].decode().strip())
            data = f.read(size)
            if size % 2:
                f.read(1)
            if name.startswith("control.tar"):
                break
    if name.endswith(".xz"):
        data = lzma.decompress(data)
    elif not name.endswith(".gz") and name != "control.tar":
        raise ValidationError(f"{path}: its {name} is compressed in a way this cannot read")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        member = next(m for m in tar.getmembers() if m.name.lstrip("./") == "control")
        text = tar.extractfile(member).read().decode()
    fields, key = {}, None
    for line in text.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line
        elif ":" in line:
            key, _, value = line.partition(":")
            fields[key] = value.strip()
    return fields
