import base64
import os

from fabriclib.common.errors import ValidationError
from fabriclib.pki.common.ca_files import ca_files
from fabriclib.pki.common.openssl import openssl
from fabriclib.pki.common.to_pem import to_pem
from fabriclib.pki.scep.common.enrol_inputs import enrol_inputs
from fabriclib.pki.scep.constants import CHALLENGES_FILE, RA_CERT
from fabriclib.pki.scep.create_challenge import create_challenge
from fabriclib.pki.scep.make_mobileconfig import make_mobileconfig


def enrol_apple(v, actor, name, device="", ssid="", wired=False, source="web", store=CHALLENGES_FILE):
    """Purpose: an Apple configuration profile for one iPhone, iPad or Mac (manual 1.5.3.5): it trusts fabric's root,
             enrols over SCEP with a one-time challenge made now for this person, and joins 802.1X with the
             certificate (Wi-Fi when an SSID is given, wired when asked).
    Inputs:  v — settings (install_webui, deploy_base_dir, hostname_stepca, hostname_radius, domain, ca_name,
             scep_challenge_minutes); actor — the person (the challenge is bound to them); name — the certificate's
             CN; device — a directory device to link the certificate to when it is issued, or ""; ssid — the Wi-Fi
             network's name, 1 to 32 bytes, or "" for none; wired — bool (a Mac's Ethernet port); source — the
             audit's; store — the challenge store.
    Returns: {"filename" (<name>.mobileconfig), "profile_b64", "expires", "id", "cn"}.
    Fails:   ValidationError: enrol_inputs' (no web console, a bad name, an unknown device); an SSID that is too long
             or holds control characters; SCEP not set up yet (no RA certificate: run setup); OSError reading the root
             CA; the store's errors (create_challenge).
    Feeds:   agent/post_enrol (POST /v1/pki/enrol/apple) <- the web console's Enrol a device."""
    name, device = enrol_inputs(v, name, device)
    ssid = str(ssid or "").strip()
    if len(ssid.encode()) > 32 or any(ord(ch) < 32 or ord(ch) == 127 for ch in ssid):
        raise ValidationError("the Wi-Fi name must be at most 32 bytes, without control characters")
    root_path, _ = ca_files(v)
    if not os.path.exists(os.path.join(os.path.dirname(root_path), RA_CERT)):
        raise ValidationError("SCEP is not set up on this host yet: run `sudo fabricctl setup` once (its pki step)")
    with open(root_path) as f:
        root_der = openssl("x509", "-outform", "DER", data=to_pem(f.read(), "cert")[0].encode())
    made = create_challenge(v, actor, name, device, source=source, store=store)
    profile = make_mobileconfig(v, name, made["challenge"], root_der, ssid=ssid, wired=bool(wired))
    return {"filename": f"{name}.mobileconfig", "profile_b64": base64.b64encode(profile).decode(),
            "expires": made["expires"], "id": made["id"], "cn": name}
