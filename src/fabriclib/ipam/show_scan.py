def show_scan(result):
    """Purpose: a scan's result as text (manual 1.10.4.21): every address that answered, how, and what the plan and
             Kea know of it; those nobody recorded marked, with the command that would record each.
    Inputs:  result — scan_subnet's result.
    Returns: str, ending in a newline.
    Fails:   never for scan_subnet's result.
    Feeds:   run_ipam_command (scan)."""
    sub = result["subnet"]
    lines = [f"scanned {sub['cidr']}" + (f" ({sub['name']})" if sub["name"] else "")
             + f": {result['scanned']} addresses, {len(result['answering'])} answering, "
             + f"{result['unrecorded']} in use but unrecorded"]
    for f in result["answering"]:
        what = {"recorded": f"{f['kind']} {f['name']}".strip(), "lease": f"lease {f['name']}".strip(),
                "unrecorded": "IN USE, UNRECORDED"}[f["status"]]
        lines.append(f"  {f['ip']:<15} {f['mac'] or '-':<17} {f['how']:<8} {what}" + (f"  ({f['note']})"
                                                                                       if f["note"] else ""))
    for f in result["answering"]:
        if f["status"] != "unrecorded":
            continue
        if f["mac"]:
            lines.append(f"  to reserve it: sudo fabricctl ipam address add {f['ip']} --kind reservation "
                         f"--mac {f['mac']} --name <name>")
        else:
            lines.append(f"  to record it: sudo fabricctl ipam address add {f['ip']} --kind static --name <name>")
    return "\n".join(lines) + "\n"
