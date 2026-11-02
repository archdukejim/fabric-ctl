from webui.views.render_page import render_page


def ipam_scan(ctx, scan, result=None, pick=""):
    """Purpose: The scan page, a page of Networks (manual 1.10.4.40.1, 1.10.4.22, 1.10.4.36): whether the signed-in
             person may scan here and why not; one of this site's subnets picked and scanned at once (Scan now); after
             a scan, every address that answered, and Record a find (picked from those in use but unrecorded), which
             waits for Networks' Apply.
    Inputs:  ctx — page context; scan — scannable_subnets' dict ({"site", "subnets", "may", "why"}); result —
             scan_subnet's result, or None before a scan; pick — the subnet to preselect (its network or name).
    Returns: HTML str.
    Fails:   Jinja2 errors propagate.
    Feeds:   src/webui/routes/networks_scan_page, networks_scan_post; the dev preview."""
    unrecorded = [f for f in (result or {}).get("answering") or [] if f.get("status") == "unrecorded"]
    return render_page("ipam_scan", ctx=ctx, page="/networks", scan=scan, result=result, pick=pick,
                       unrecorded=unrecorded)
