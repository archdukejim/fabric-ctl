from fabriclib.common.errors import ValidationError
from fabriclib.common.load_vars import load_vars
from fabriclib.common.write_audit import write_audit
from fabriclib.federation.common.federation_lock import federation_lock
from fabriclib.federation.common.load_registry import load_registry
from fabriclib.federation.common.save_registry import save_registry
from fabriclib.pki.revoke_cert import revoke_cert
from fabriclib.secrets.load_secrets import load_secrets
from fabriclib.secrets.save_secrets import save_secrets


def remove_site(actor, site, source="cli", v=None):
    """Purpose: on a site's parent (the root, or the site it is nested under): forget a site that joined here —
             a disposable lab torn down, or one moved elsewhere (manual 1.9.5.1).
    Inputs:  actor — str (audit); site — its name; source — default "cli"; v — fabric vars for OpenBao
             (default: read from vars.yaml).
    Returns: the removed record (dict); its DNS link key (federation_tsig[site]) is deleted too. The caller
             applies, so the delegation and the secondary zone go.
    Fails:   ValidationError "no site <x> joined here"; OSError / yaml errors from the registry; subprocess errors
             from publishing the CRL.
    Feeds:   run_federation_command (remove).
    Notes:   the site's CA is revoked (decision 2.1.5.10; record["revoked"] says so, or why it could not be: a site CA
             signed by a brought-in root is revoked where the root key is). A site invited again under the same name
             gets a new CA. Audited as FED_SITE_REMOVE (and PKI_REVOKE)."""
    with federation_lock():
        registry = load_registry()
        record = registry["sites"].pop(site, None)
        if record is None:
            raise ValidationError(f"no site {site} joined here")
        save_registry(registry)
        stored = load_secrets(v=v)
        update = {}
        keys = dict(stored.get("federation_tsig") or {})                # the DNS link
        if keys.pop(site, None) is not None:
            update["federation_tsig"] = keys
        if update:
            save_secrets(update, v=v)
    write_audit(actor, "FED_SITE_REMOVE", f"site={site} ca_serial={record.get('ca_serial', '')}", source)
    record["revoked"] = ""
    if record.get("ca_serial"):              # its CA is revoked, so its certificates stop being trusted (2.1.5.10)
        try:
            revoke_cert(v or load_vars(), actor, record["ca_serial"], "cessationOfOperation", source)
            record["revoked"] = "its CA is revoked (in the CRL now)"
        except ValidationError as e:
            record["revoked"] = f"its CA could not be revoked here: {e}"
    return record
