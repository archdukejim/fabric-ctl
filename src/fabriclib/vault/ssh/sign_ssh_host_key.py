from fabriclib.common.errors import ValidationError
from fabriclib.vault.common.bao_request import bao_request
from fabriclib.vault.ssh.constants import HOST_MOUNT, HOST_ROLE, HOST_TTL


def sign_ssh_host_key(v, token, key_line, principals, key_id):
    """Purpose: one SSH host certificate from OpenBao's host CA (manual 1.6.11.9.8): the role HOST_ROLE, 30 days, the
             principals fabric chose (never the machine).
    Inputs:  v — settings (bao_request's); token — a fabric-setup token; key_line — "<type> <base64>" (judged by
             plan_host_certs); principals — list of str; key_id — str, e.g. "fabric-host:ws2404:<UTC time>".
    Returns: the certificate line ("<type>-cert-v01@openssh.com <base64>").
    Fails:   ValidationError when OpenBao refuses (the role gone: certificates turned off meanwhile; setup's policy
             without the host engine: run the vault step) or answers no certificate; from bao_request when OpenBao is
             unreachable or sealed.
    Feeds:   vault/ssh/sign_ssh_hosts."""
    status, data = bao_request(v, "POST", f"{HOST_MOUNT}/sign/{HOST_ROLE}", token=token, body={
        "public_key": key_line, "valid_principals": ",".join(principals), "cert_type": "host", "ttl": HOST_TTL,
        "key_id": key_id})
    if status == 403:
        raise ValidationError("OpenBao refused fabric's setup role for SSH host certificates: run `sudo fabricctl "
                              "setup --step vault` once, then try again")
    cert = ((data.get("data") or {}).get("signed_key") or "").strip() if status == 200 else ""
    if not cert:
        raise ValidationError(f"OpenBao did not sign the host key: {data.get('errors') or status}")
    return cert
