# fabriclib/ipam/scancontrol

Scans at another site (manual 1.10.4.36; decision 2.1.10.38): someone with the grants' networks `scan` right at a
site asks it to scan one of its subnets through AD; that site's plan poll checks the person again by its own reading
of the grants, runs the scan and writes the answer back.

| File | What |
|---|---|
| `limits.py` | The limits: the largest network scanned at once, a request kept a day, run within an hour, four pending per site, the result's size, one run per poll, the command's wait |
| `read_scan_requests.py` | A site's scan requests and their answers, from the DC (operation `read_scan_requests`) |
| `write_scan_request.py` | One change to a request in the domain, at a writable DC: added by the asking site, answered or removed by the serving site |
| `request_scan.py` | Ask another site to scan one of its subnets: the caller's `scan` there checked, written into AD naming the person, audited |
| `run_scan_requests.py` | At the serving site, the plan poll's step: refuse a request not made by a fabric DC's agent or naming a person without `scan` here, run the rest, answer, remove old ones |
| `bound_result.py` | A scan's result as the JSON written back, never longer than the limit (the unrecorded first) |
| `list_scan_requests.py` | A site's requests as the command shows them: newest first, a day's worth, the late marked |
| `show_scan_requests.py` | Them as text for `fabricctl ipam scan-requests` |
| `run_scan_command.py` | `fabricctl ipam scan <subnet> --site S` and `scan-requests` |
