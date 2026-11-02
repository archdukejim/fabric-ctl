from fabriclib.dhcp.common.apply_dhcp_change import apply_dhcp_change


def report_change(v, out, bare, apply=apply_dhcp_change):
    """Purpose: report a change to a plan: its warnings, then apply it when it is this site's plan (manual 1.10.4.35:
             another site's takes it within 30 s, its plan poll).
    Inputs:  v — fabric vars; out — edit_plan's result; bare — the bare flags given (--no-apply); apply —
             apply_dhcp_change (tests give their own).
    Returns: exit status (apply_dhcp_change's for this site, 0 for another).
    Fails:   what apply_dhcp_change raises.
    Feeds:   run_plan_change."""
    for w in out["warnings"]:
        print(f"warning: {w}")
    if out["site"] != v.get("site_name"):
        print(f"written to {out['site']}'s plan: that site's Kea takes it within 30 s (fabric-plan-watch)")
        return 0
    return apply(["--no-apply"] if "--no-apply" in bare else [])
