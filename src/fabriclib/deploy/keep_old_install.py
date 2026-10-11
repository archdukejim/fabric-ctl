def keep_old_install(data):
    """Purpose: what an install from before 0.7.0 keeps when a newer fabric renders it, written into its settings once
             so it is saved with them: its domain controller's name, which was the host's (2.1.6.45, manual
             1.6.5.23), so nothing in the domain is renamed; and its uid/gid numbering (2.1.6.46, manual 1.6.3.17):
             the root's block from where its people's range started (the users OU's uid_range, read this once),
             posix_id_block as it was (100000 unless set).
    Inputs:  data — the install's settings as saved (modified in place); a vars file without dc_name comes from before
             0.7.0 (setup sets it on every install since); one with dc_name is left alone.
    Returns: list of str, one line per setting kept.
    Fails:   never — dict operations only.
    Feeds:   setup/upgrade_vars (an existing install's settings before setup asks anything), deploy/apply_deployment
             (an apply before setup has run on the upgraded package)."""
    kept = []
    if data.get("dc_name"):                 # set by setup from 0.7.0 on: nothing to keep
        return kept
    if data.get("hostname"):
        data["dc_name"] = str(data["hostname"]).lower()
        kept.append(f"the domain controller keeps its name {data['dc_name']} (dc_name, 2.1.6.45)")
    users = next((o for o in data.get("ldap_organizational_units") or []
                  if isinstance(o, dict) and o.get("name") == "users" and o.get("uid_range")), None)
    if not data.get("posix_id_start") and users:
        try:
            data["posix_id_start"] = int(str(users["uid_range"]).split("-")[0])
        except ValueError:
            data["posix_id_start"] = 5001
        data.setdefault("posix_id_block", 100000)
        kept.append(f"the uid/gid numbers stay as they are: the root's block from {data['posix_id_start']}, "
                    f"{data['posix_id_block']} long (2.1.6.46)")
    return kept
