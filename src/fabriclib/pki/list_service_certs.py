import os

from fabriclib.common.errors import ValidationError
from fabriclib.pki.common.describe_cert import describe_cert
from fabriclib.setup.service_cert_targets import cert_file, service_cert_targets


def list_service_certs(ctx):
    """Purpose: fabric's own service certificates (manual 1.5.1.2, 1.5.1.9.1) as they are on disk now: one row for
             each certificate setup and the daily renewal keep, read from its first destination.
    Inputs:  ctx — SetupContext with its vars loaded (service_cert_targets' hostname_* settings, deploy_base).
    Returns: list of {"cn", "serial", "subject", "issuer", "sans", "not_before", "not_after", "sha256", "services"
             (what reloads or restarts when it is replaced), "path"}; a certificate not issued yet (its file
             missing or unreadable) is left out.
    Fails:   ValidationError naming a missing hostname_* setting (service_cert_targets' KeyError): settings no
             setup run has rendered.
    Feeds:   pki/list_certs, pki/revoke_cert (a service certificate is replaced before it is revoked)."""
    out = []
    try:
        targets = service_cert_targets(ctx)
    except KeyError as exc:
        raise ValidationError(f"the setting {exc.args[0]} is missing, so fabric's own certificates cannot be found: "
                              "run `sudo fabricctl setup`") from None
    for cn, _sans, dests, services, _exact in targets:
        path = cert_file(*dests[0])
        try:
            with open(path) as f:
                info = describe_cert(f.read())
        except (OSError, ValidationError):       # not issued yet, or not a certificate
            continue
        out.append({"cn": cn, "serial": info["serial"].replace(":", "").upper().lstrip("0") or "0",
                    "subject": info["subject"], "issuer": info["issuer"], "sans": info["sans"],
                    "not_before": info["not_before"], "not_after": info["not_after"], "sha256": info["sha256"],
                    "services": list(services), "path": os.path.abspath(path)})
    return out
