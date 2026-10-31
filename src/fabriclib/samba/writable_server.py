from fabriclib.common.errors import ValidationError


def writable_server(v, to):
    """Purpose: the one choice of the DC a write to the domain goes to (decision 2.1.6.52): this site's
             own, or at a site whose DC is read-only the writable DC it replicates from (`ad_join_server`), since a
             read-only DC takes no writes.
    Inputs:  v — fabric vars (ad_dc_type, ad_join_server); to — what the write is, ending the refusal's sentence
             ("make the host's account at").
    Returns: None (this site's DC) or the writable DC's address (str, trimmed).
    Fails:   ValidationError for a read-only DC with no writable DC known, before anything is written.
    Feeds:   setup/common/host_identity, undo/remove_host_account."""
    if v.get("ad_dc_type") != "rodc":
        return None
    server = str(v.get("ad_join_server") or "").strip()
    if not server:
        raise ValidationError("this site's domain controller is read-only and no writable domain controller is known "
                              f"(ad_join_server) to {to}")
    return server
