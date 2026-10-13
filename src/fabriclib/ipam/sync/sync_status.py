from fabriclib.ipam.options.watch_state import load_watch_state


def sync_status(v, load=load_watch_state):
    """Purpose: what the plan poll last reported, shown beside the Sync now button (decision 2.1.10.29, manual
             1.10.4.28.2): when it last rendered Kea, the DC's USN it last saw, and whether the plan's published names
             or subnets wait for an apply or Sync now (DNS pending). Read from what the poll keeps; the DC is not asked.
    Inputs:  v — fabric vars (install_kea); load — load_watch_state (tests give their own).
    Returns: {"kea" (bool: Kea installed here), "polled" (bool: the poll has run since the last reset), "usn",
             "rendered" (when the poll last rendered Kea, "" never), "dns_pending" (bool)}.
    Fails:   OSError other than a missing file (load_watch_state).
    Feeds:   ipam/networks_overview (the Networks tab's Sync now card)."""
    if not v.get("install_kea"):
        return {"kea": False, "polled": False, "usn": None, "rendered": "", "dns_pending": False}
    state, dns = load("plan-watch"), load("plan-dns")
    return {"kea": True, "polled": bool(state), "usn": state.get("usn"), "rendered": state.get("rendered") or "",
            "dns_pending": bool(state.get("dns")) and state["dns"] != dns.get("dns")}
