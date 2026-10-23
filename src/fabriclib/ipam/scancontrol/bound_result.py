import json

from fabriclib.ipam.scancontrol.limits import RESULT_LIMIT

ROW = ("ip", "mac", "how", "status", "kind", "name", "note")


def bound_result(result, limit=RESULT_LIMIT):
    """Purpose: a scan's result as the JSON written back on its request in AD (decision 2.1.10.38, manual
             1.10.4.36), never longer than the limit: the subnet, when, how many probed, answering and unrecorded,
             and the answering rows, the unrecorded first; rows that do not fit are left out and counted.
    Inputs:  result — scan_subnet's result; limit — the most characters (default RESULT_LIMIT).
    Returns: str, compact JSON: {"subnet", "at", "scanned", "answering" (int, every row that answered), "unrecorded",
             "rows" [{"ip", "mac", "how", "status", "kind", "name", "note"}], "truncated" (rows left out)}.
    Fails:   ValueError when even the summary does not fit (a limit below a few hundred characters).
    Feeds:   run_scan_requests."""
    rows = sorted(({k: r.get(k, "") for k in ROW} for r in result["answering"]),
                  key=lambda r: (r["status"] != "unrecorded",))
    head = {"subnet": result["subnet"], "at": result["at"], "scanned": result["scanned"],
            "answering": len(result["answering"]), "unrecorded": result["unrecorded"]}

    def text(kept):
        return json.dumps({**head, "rows": rows[:kept], "truncated": len(rows) - kept}, separators=(",", ":"))

    if len(text(0)) > limit:
        raise ValueError(f"a scan's summary does not fit in {limit} characters")
    low, high = 0, len(rows)            # the most rows that fit
    while low < high:
        mid = (low + high + 1) // 2
        if len(text(mid)) <= limit:
            low = mid
        else:
            high = mid - 1
    return text(low)
