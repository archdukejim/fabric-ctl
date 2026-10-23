from fabriclib.common.errors import ValidationError

# the Ubuntu releases fabric's hosts run (2.1.1.1, 2.1.1.10, 2.1.1.43) and their archive names
RELEASES = {"22.04": "jammy", "24.04": "noble", "26.04": "resolute"}
OS_RELEASE = "/etc/os-release"


def ubuntu_release(release=None, os_release=OS_RELEASE):
    """Purpose: the Ubuntu release an offline bundle's packages are for (decision 2.1.14.16): the one named, or this
             machine's.
    Inputs:  release — "24.04" style str, or None for this machine's (VERSION_ID in os_release); os_release — path.
    Returns: (version, codename), e.g. ("24.04", "noble").
    Fails:   ValidationError when the release is not one fabric's hosts run, or none is named and this machine is
             not Ubuntu (then --ubuntu is needed).
    Feeds:   export_bundle, check_bundle, extract_bundle_apt."""
    if release is None:
        fields = {}
        try:
            with open(os_release) as f:
                for line in f:
                    key, _, value = line.strip().partition("=")
                    fields[key] = value.strip('"')
        except OSError:
            pass
        if fields.get("ID") != "ubuntu":
            raise ValidationError("this machine is not Ubuntu: name the offline host's release with --ubuntu "
                                  f"({', '.join(RELEASES)})")
        release = fields.get("VERSION_ID", "")
    if release not in RELEASES:
        raise ValidationError(f"Ubuntu {release} is not a release fabric's hosts run ({', '.join(RELEASES)})")
    return release, RELEASES[release]
