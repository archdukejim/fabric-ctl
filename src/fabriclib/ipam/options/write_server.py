from fabriclib.common.errors import ValidationError


def write_server(v):
    """Purpose: the DC a change to the DHCP options is written at (decision 2.1.10.23, manual 1.10.4.24.2): this site's
             own, or at a site whose DC is read-only the writable DC it replicates from (`ad_join_server`), as 2.1.6.52
             does for the host's account.
    Inputs:  v — fabric vars (ad_dc_type, ad_join_server).
    Returns: None (this site's DC) or the writable DC's address (str).
    Fails:   ValidationError for a read-only DC with no writable DC known, before anything is written.
    Feeds:   ipam/common/edit_options, set_option_editor."""
    if v.get("ad_dc_type") != "rodc":
        return None
    server = str(v.get("ad_join_server") or "").strip()
    if not server:
        raise ValidationError("this site's domain controller is read-only and no writable domain controller is known "
                              "(ad_join_server) to write the change at: make it at the site above")
    return server
