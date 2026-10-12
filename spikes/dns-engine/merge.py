"""Convert each downloaded list with fabric's own converter and merge them into one response policy zone, deduplicated:
the BIND-only side of the dns-engine spike (manual 2.3.1.18). Throwaway (global Rule 4).

    python3 merge.py <raw folder> <out.rpz> <list ids...>

Prints one line of JSON: rules and records per list, the merged zone's records, and what deduplication saved.
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "src"))
from fabriclib.dns_filter.convert_list import convert_list  # noqa: E402

raw, out, ids = sys.argv[1], sys.argv[2], sys.argv[3:]
blocks, allows, per_list, total = set(), set(), {}, 0
for i in ids:
    path = os.path.join(raw, f"filter_{i}.txt")
    if not os.path.exists(path):
        continue
    conv = convert_list(open(path, encoding="utf-8", errors="replace").read(), f"list{i}.rpz")
    per_list[i] = {"rules": conv["rules"], "records": conv["records"]}
    total += conv["records"]
    for line in conv["zone_text"].splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "CNAME":
            (allows if parts[2] == "rpz-passthru." else blocks).add(parts[0])
blocks -= allows                      # an allow in any list wins, as it does across separate zones
with open(out, "w") as f:
    f.write("$TTL 300\n@ SOA localhost. hostmaster.merged.rpz. 1 3600 600 86400 300\n@ NS localhost.\n")
    f.writelines(f"{n} CNAME .\n" for n in sorted(blocks))
    f.writelines(f"{n} CNAME rpz-passthru.\n" for n in sorted(allows))
merged = len(blocks) + len(allows)
print(json.dumps({"per_list": per_list, "records_separate": total, "records_merged": merged,
                  "saved_pct": round(100 * (1 - merged / total), 1) if total else 0}))
