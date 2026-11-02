def show_scan_requests(site, rows):
    """Purpose: a site's scan requests as `fabricctl ipam scan-requests` prints them (manual 1.10.4.36): each with
             who asked, when, its state, and a done one's answer (every address that answered, the unrecorded first).
    Inputs:  site — the site; rows — list_scan_requests' rows.
    Returns: str, lines ending in a newline.
    Fails:   KeyError for a row that is not list_scan_requests'.
    Feeds:   run_scan_command."""
    if not rows:
        return f"no scan requests at {site} in the last day\n"
    lines = []
    for r in rows:
        state = r["state"] + (" (not picked up yet: is the site running?)" if r.get("late") else "")
        lines.append(f"{r['id']}  {r['cidr']} ({r['subnet']})  asked by {r['actor']}@{r['requested_by']} at "
                     f"{r['created']}: {state}")
        res = r.get("result")
        if r["state"] == "done" and isinstance(res, dict) and "rows" in res:
            lines.append(f"  scanned {res['at']}: {res['scanned']} addresses, {res['answering']} answering, "
                         f"{res['unrecorded']} in use but unrecorded"
                         + (f" ({res['truncated']} rows left out)" if res.get("truncated") else ""))
            for f in res["rows"]:
                what = {"recorded": f"{f['kind']} {f['name']}".strip(), "lease": f"lease {f['name']}".strip(),
                        "unrecorded": "IN USE, UNRECORDED"}.get(f["status"], f["status"])
                lines.append(f"  {f['ip']:<15} {f['mac'] or '-':<17} {f['how']:<8} {what}"
                             + (f"  ({f['note']})" if f["note"] else ""))
        elif r["state"] in ("refused", "expired") and isinstance(res, dict):
            lines.append(f"  {res.get('error', '')}")
    return "\n".join(lines) + "\n"
