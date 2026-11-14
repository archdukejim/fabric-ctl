import subprocess

from fabriclib.common.errors import ValidationError
from fabriclib.pki.pick_up_cert import pick_up_cert
from fabriclib.setup.errors import SetupError
from fabriclib.setup.issue_service_cert import issue_service_cert
from fabriclib.setup.service_cert_targets import service_cert_targets


def replace_service_cert(ctx, cn):
    """Purpose: before one of fabric's own service certificates is revoked, issue its successor and put it in use
             (manual 1.5.1.9.4): installed where the old one was, each service that uses it reloaded or restarted as
             on renewal (2.1.5.4), so no client that checks the CRL loses the service.
    Inputs:  ctx — SetupContext with its vars loaded; cn — the certificate's name (list_service_certs' "cn").
    Returns: {service: how it took the new certificate ("reloaded", "restarted", ...)}.
    Fails:   ValidationError, saying why, when no service certificate has that name, or the new one cannot be issued
             or installed (Step-CA down or refusing): the caller then revokes nothing. A service that cannot take it
             (CalledProcessError) is a ValidationError too, after the new certificate is in place.
    Feeds:   pki/revoke_cert."""
    target = next((t for t in service_cert_targets(ctx) if t[0] == cn), None)
    if target is None:
        raise ValidationError(f"{cn} is not one of fabric's service certificates")
    _cn, sans, dests, services, _exact = target
    try:
        issue_service_cert(ctx, cn, sans, dests)
    except (SetupError, OSError, subprocess.CalledProcessError) as exc:
        raise ValidationError(f"a new certificate for {cn} could not be issued, so nothing was revoked: "
                              f"{str(exc).strip()[-300:]}")
    done = {}
    for unit in services:
        try:
            done[unit] = pick_up_cert(unit)
        except subprocess.CalledProcessError as exc:
            raise ValidationError(f"the new certificate for {cn} is installed, but {unit} did not take it "
                                  f"({exc}); the old one was not revoked")
    return done
