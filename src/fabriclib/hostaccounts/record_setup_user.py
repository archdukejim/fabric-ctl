from fabriclib.hostaccounts.approvals import load_approvals, save_approvals


def record_setup_user(config_dir, login):
    """Purpose: the account that ran setup recorded once, as the host's root break glass until local-admin takes over
             (2.1.6.78): it is listed as the setup account, and reminded of like any other until it is removed or
             approved. A later setup run by another account keeps the first.
    Inputs:  config_dir — the install's config folder; login — the account that ran sudo (sudo_owner), "root" when
             setup ran as root without sudo (then nothing is recorded: root is never listed).
    Returns: bool, whether it was recorded now.
    Fails:   ValueError, OSError from the record (approvals).
    Feeds:   setup/create_admin."""
    data = load_approvals(config_dir)
    if data["setup_user"] or not login or login == "root":
        return False
    data["setup_user"] = login
    save_approvals(config_dir, data)
    return True
