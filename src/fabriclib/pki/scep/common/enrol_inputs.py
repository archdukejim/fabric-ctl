from fabriclib.common.errors import ValidationError
from fabriclib.directory.require_device import require_device
from fabriclib.pki.scep.constants import NAME_RE


def enrol_inputs(v, name, device=""):
    """Purpose: check what both kinds of enrolment are asked for: the certificate's name and the device to link.
    Inputs:  v — settings (install_webui; the directory, for the device); name — str, the CN (a device-style label);
             device — str, a directory device's name, or "" for none.
    Returns: (name, device) stripped, the name in lower case.
    Fails:   ValidationError: no web console (enrolment lives there, its hooks on the console's name: 1.5.3.3); a name
             that is not 1-63 of a-z 0-9 and inner dashes; require_device's "no device named ...".
    Feeds:   enrol_apple, enrol_p12."""
    if not v.get("install_webui"):
        raise ValidationError("device enrolment needs the web console (install_webui): its SCEP hook is served there")
    name = str(name or "").strip().lower()
    if not NAME_RE.match(name):
        raise ValidationError("the name must be 1 to 63 letters, digits and dashes (e.g. alice-iphone)")
    device = str(device or "").strip()
    if device:
        require_device(v, device)
    return name, device
