from webui.views.render_page import render_page


def ipam_scan(ctx, subnets, result=None, msg="", err="", pick="", policy=None, policy_error=""):
    """Purpose: The scan page (manual 1.10.4.22, 1.10.4.27): the scan policy in force here and where it comes from (no
             Scan button where it denies); pick one of this site's subnets and scan it; after a scan, every
             address that answered, and for each in use but unrecorded the offer to record it ("make it a
             reservation?" with the MAC ARP saw, else a static address). Its own page, view and template, so the
             Networks tab can link it or include it as it is.
    Inputs:  ctx — page context; subnets — scannable_subnets' list; result — scan_subnet's result, or None before a
             scan; msg, err — the outcome of the last change; pick — the subnet to preselect (its network or name,
             as the Networks tab's subnet view links it; "" none); policy — the effective scan policy
             (read_scan_policy's result) or None; policy_error — why it could not be read ("" none).
    Returns: HTML str.
    Fails:   jinja2 errors propagate (render_page).
    Feeds:   src/webui/routes/networks_scan_page, networks_scan_post."""
    return render_page("ipam_scan", ctx=ctx, tab="networks", subnets=subnets, result=result, msg=msg, err=err,
                       pick=pick, policy=policy, policy_error=policy_error)
