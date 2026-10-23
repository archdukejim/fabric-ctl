# fabriclib/ipam/sync

Sync now (manual 1.10.4.28; decision 2.1.10.29): the plan poll at once, and the plan's DNS published by the quick path,
on demand; never an apply; and what the poll last reported, shown beside the console's button.

| File | What |
|---|---|
| `sync_plan.py` | Sync now: the person's networks plan right checked; refused while an apply runs; the poll forced; BIND's records published when DNS waits; audited |
| `sync_status.py` | What the poll last reported (when it rendered Kea, whether DNS waits), from what it keeps |
