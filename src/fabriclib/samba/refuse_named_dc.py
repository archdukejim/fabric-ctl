from fabriclib.common.errors import ValidationError


def refuse_named_dc(given, installed, source):
    """Purpose: refuse a settings file that names the domain controller for a new install (2.1.6.65, manual 1.6.5.26):
             fabric names its DCs itself, and nobody gives one a name. On an installed host the DC keeps its own
             name, so the file's is not this check's (the caller keeps the installed one).
    Inputs:  given — the file's settings (dict); installed — bool, this host's DC is installed (samba/dc_provisioned);
             source — what the file is, for the message (e.g. "the vars file x.yaml").
    Returns: None.
    Fails:   ValidationError when the file sets dc_name (a value, not an empty key) and no DC is installed: saying
             fabric names DCs itself, and that nothing was changed.
    Feeds:   setup/collect_vars (`fabricctl setup --file`, a checkout's custom-vars.yaml),
             settings/run_settings_command (`fabricctl settings import`)."""
    name = (given or {}).get("dc_name") if isinstance(given, dict) else None
    if installed or name in (None, ""):
        return
    raise ValidationError(f"{source} names the domain controller (dc_name: {name}), but fabric names its domain "
                          "controllers itself (2.1.6.65): dc-0001 for a new domain, the next free dc-NNNN, given by "
                          "the upstream, for a site joining one. Remove dc_name from the file; nothing was changed")
