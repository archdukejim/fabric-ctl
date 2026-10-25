from fabriclib.hostaccounts.list_local_admins import list_local_admins


def local_account_reminders(config_dir, listed=None):
    """Purpose: the routine reminder of every local root or administrator account OpenBao does not manage and the
             Enterprise Admin has not approved (2.1.6.78): shown on each view of the console's top bar and Overview and
             each `fabricctl doctor`, until the account is removed or approved.
    Inputs:  config_dir — the install's config folder; listed — list_local_admins's result (default: read now).
    Returns: list of {"kind": "local-account", "name", "text"}.
    Fails:   OSError, ValueError from list_local_admins.
    Feeds:   system/host_reminders (the console), setup/verify_install (doctor)."""
    out = []
    for row in listed if listed is not None else list_local_admins(config_dir):
        if row["approved"] or row.get("managed"):
            continue
        who = "the account that ran setup, " if row["setup"] else ""
        out.append({"kind": "local-account", "name": row["name"],
                    "text": f"the local account {row['name']} ({who}{', '.join(row['why'])}) has root or "
                            "administrator rights on this domain controller's host that OpenBao does not manage: "
                            "remove it, or approve it as break glass "
                            f"(sudo fabricctl host accounts approve {row['name']}, 2.1.6.78)"})
    return out
