def keep_old_install(data):
    """Purpose: what an install from before 0.7.0 keeps when a newer fabric renders it, written into its settings once
             so it is saved with them: its domain controller's name, which was the host's (2.1.6.45, manual
             1.6.5.23), so nothing in the domain is renamed.
    Inputs:  data — the install's settings as saved (modified in place); a vars file without dc_name comes from before
             0.7.0 (setup sets it on every install since).
    Returns: list of str, one line per setting kept.
    Fails:   never — dict operations only.
    Feeds:   setup/upgrade_vars (an existing install's settings before setup asks anything), deploy/apply_deployment
             (an apply before setup has run on the upgraded package)."""
    kept = []
    if not data.get("dc_name") and data.get("hostname"):
        data["dc_name"] = str(data["hostname"]).lower()
        kept.append(f"the domain controller keeps its name {data['dc_name']} (dc_name, 2.1.6.45)")
    return kept
