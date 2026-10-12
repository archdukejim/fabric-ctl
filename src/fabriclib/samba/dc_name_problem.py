import re

_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")


def dc_name_problem(name, netbios=""):
    """Purpose: why a name cannot be the domain controller's (2.1.6.45, manual 1.6.5.23), if it cannot: it is the DC's
             host name in the AD domain and its NetBIOS name, so one label of at most 15 letters, digits or hyphens.
    Inputs:  name — str, the DC's name as given (case is ignored); netbios — str, the domain's NetBIOS name
             (ad_netbios), which the DC's may not equal (Samba refuses to provision it), "" to skip that check.
    Returns: str, the problem; "" when the name can be used.
    Fails:   never.
    Feeds:   setup/ask_dc_name (asked again at once), deploy/check_samba_settings (deploy refuses)."""
    low = str(name or "").strip().lower()
    if not _NAME.match(low):
        return (f"{name!r}: one label of 1-15 letters, digits or hyphens, not starting or ending with a hyphen "
                "(the DC's NetBIOS name)")
    if low.isdigit():
        return f"{name!r}: not only digits (Windows refuses such a computer name)"
    if low == "localhost":
        return "not localhost"
    if netbios and low == str(netbios).lower():
        return f"{name!r} is the domain's own NetBIOS name: the DC needs a name of its own"
    return ""
