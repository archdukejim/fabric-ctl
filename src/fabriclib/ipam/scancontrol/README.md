# fabriclib/ipam/scancontrol

Scans from the top down (manual 1.10.4.29; decision 2.1.10.30): a site above asks a branch to scan one of its subnets
through AD, the branch's plan poll runs it and writes the answer back; the sites above decide whether a branch's own
admins may scan locally (off by default; the top always may).

| File | What |
|---|---|
| `limits.py` | The limits: a request kept a day, run within an hour, four pending per branch, the result's size, one run per poll |
| `local_scan_state.py` | Whether a site's own admins may scan, and who decided: the top always, elsewhere only when set from above |
| `read_local_scan.py` | That, read from the DC (or this site's kept copy when the DC does not answer; refused with neither) |
| `set_local_scan.py` | Set it for a site below, from a site above: checked, written at a writable DC, audited |
| `show_local_scan.py` | It as text for `fabricctl ipam local-scan` |
| `read_scan_requests.py` | A site's scan requests and their answers, from the DC (operation `read_scan_requests`) |
| `write_scan_request.py` | One change to a request in the domain: added from above, answered or removed by the branch |
| `request_scan.py` | Ask a site below to scan one of its subnets: checked, written into AD, audited |
| `run_scan_requests.py` | At the branch, the plan poll's step: run what was asked from above, answer it, remove old requests |
| `bound_result.py` | A scan's result as the JSON written back, never longer than the limit (the unrecorded first) |
| `list_scan_requests.py` | A site's requests as the asking console and the command show them |
| `show_scan_requests.py` | Them as text for `fabricctl ipam scan-requests` |
| `run_scan_command.py` | `fabricctl ipam scan <subnet> --site S`, `scan-requests`, `local-scan` |
