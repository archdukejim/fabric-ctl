# fabriclib/ipam/scanpolicy

The scan policy (manual 1.10.4.27; decision 2.1.10.28): whether a scan may run at a site, set at the organisation's
level (allow or deny, enforced or not) and at each site's (allow, deny or inherit), kept in AD with the plan.

| File | What |
|---|---|
| `effective_scan_policy.py` | The policy in force at a site and which level decides: the organisation's when enforced, else the site's, else the organisation's, else allow |
| `read_scan_policy.py` | The policy in force at a site, read from the DC (or this site's kept copy when the DC does not answer; refused with neither) |
| `set_scan_policy.py` | Set the organisation's level or a site's: checked, written at a writable DC, audited |
| `show_scan_policy.py` | The policy as text for `fabricctl ipam scan-policy` |
| `run_scan_policy_command.py` | `fabricctl ipam scan-policy [show] / set org / set site` |
