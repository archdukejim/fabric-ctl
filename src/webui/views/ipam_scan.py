from webui.views.render_page import render_page


def ipam_scan(ctx, subnets, result=None, msg="", err="", pick="", local=None, local_error=""):
    """Purpose: The scan page (manual 1.10.4.22, 1.10.4.29): whether this site's own admins may scan here and who set
             it (no Scan button where local scans are off); pick one of this site's subnets and scan it; after a
             scan, every address that answered, and for each in use but unrecorded the offer to record it ("make it
             a reservation?" with the MAC ARP saw, else a static address). Its own page, view and template, so the
             Networks tab can link it or include it as it is.
    Inputs:  ctx — page context; subnets — scannable_subnets' list; result — scan_subnet's result, or None before a
             scan; msg, err — the outcome of the last change; pick — the subnet to preselect (its network or name,
             as the Networks tab's subnet view links it; "" none); local — read_local_scan's result or None;
             local_error — why it could not be read ("" none).
    Returns: HTML str.
    Fails:   jinja2 errors propagate (render_page).
    Feeds:   src/webui/routes/networks_scan_page, networks_scan_post."""
    return render_page("ipam_scan", ctx=ctx, tab="networks", subnets=subnets, result=result, msg=msg, err=err,
                       pick=pick, local=local, local_error=local_error)
