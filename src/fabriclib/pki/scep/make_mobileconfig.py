import plistlib
import uuid

from fabriclib.pki.scep.constants import PROVISIONER


def _payload(kind, ident, name, content):
    """Purpose: one payload of a configuration profile, with the keys every payload carries.
    Inputs:  kind — PayloadType; ident — the profile's identifier (the payload's is ident + "." + a short name);
             name — PayloadDisplayName; content — dict of the payload's own keys.
    Returns: dict, with a fresh PayloadUUID.
    Fails:   never.
    Feeds:   make_mobileconfig."""
    short = kind.replace("com.apple.", "").replace(".", "-")        # unique per payload type
    return {"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.{short}",
            "PayloadUUID": str(uuid.uuid4()).upper(), "PayloadDisplayName": name, **content}


def make_mobileconfig(v, cn, challenge, root_der, ssid="", wired=False):
    """Purpose: the Apple configuration profile of one enrolment (manual 1.5.3.5): fabric's root CA, a SCEP payload
             asking fabric's Step-CA for a certificate named cn with a one-time challenge, and the 802.1X EAP-TLS
             payloads that use it (Wi-Fi when an SSID is given; the first Ethernet port when wired).
    Inputs:  v — settings: hostname_stepca, hostname_radius, domain, ca_name (default "<domain> CA"); cn — the
             certificate's name (checked by the caller); challenge — str; root_der — the root CA certificate (DER
             bytes); ssid — the Wi-Fi network's name ("" for none); wired — bool.
    Returns: bytes, the profile as an XML property list (unsigned).
    Fails:   KeyError without hostname_stepca or domain.
    Feeds:   enrol_apple."""
    domain = v["domain"]
    ident = "fabric." + ".".join(reversed(domain.split("."))) + ".enrol." + cn
    ca_name = v.get("ca_name") or f"{domain} CA"
    root = _payload("com.apple.security.root", ident, f"{ca_name} (root)",
                    {"PayloadContent": root_der, "PayloadCertificateFileName": "fabric-root-ca.cer"})
    scep = _payload("com.apple.security.scep", ident, f"{cn} (certificate from {ca_name})", {"PayloadContent": {
        "URL": f"http://{v['hostname_stepca']}/scep/{PROVISIONER}", "Name": PROVISIONER,
        "Subject": [[["CN", cn]]], "Challenge": challenge, "Keysize": 2048, "Key Type": "RSA", "Key Usage": 5,
        "Retries": 3, "RetryDelay": 10}})
    payloads = [root, scep]
    eap = {"AcceptEAPTypes": [13], "TLSTrustedServerNames": [v.get("hostname_radius") or f"radius.{domain}"],
           "PayloadCertificateAnchorUUID": [root["PayloadUUID"]]}
    if ssid:
        payloads.append(_payload("com.apple.wifi.managed", ident, f"Wi-Fi {ssid} (802.1X)", {
            "SSID_STR": ssid, "HIDDEN_NETWORK": False, "AutoJoin": True, "EncryptionType": "Any",
            "EAPClientConfiguration": dict(eap), "PayloadCertificateUUID": scep["PayloadUUID"]}))
    if wired:
        payloads.append(_payload("com.apple.firstactiveethernet.managed", ident, "Wired 802.1X", {
            "EAPClientConfiguration": dict(eap), "PayloadCertificateUUID": scep["PayloadUUID"]}))
    profile = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": ident,
               "PayloadUUID": str(uuid.uuid4()).upper(), "PayloadDisplayName": f"{ca_name}: {cn}",
               "PayloadDescription": (f"fabric's root CA, a certificate for {cn} over SCEP (one use)"
                                      + (f", and 802.1X on {ssid}" if ssid else "")
                                      + (", wired 802.1X" if wired else "")),
               "PayloadOrganization": ca_name, "PayloadRemovalDisallowed": False, "PayloadContent": payloads}
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)
