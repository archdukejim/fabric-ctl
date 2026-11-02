import csv
import io

from fabriclib.ipam.common.site_plan import site_plan
from fabriclib.ipam.plan_rows import COLUMNS, plan_rows

# location last (2.1.10.52): the columns of an export before locations keep their places
EXPORT_COLUMNS = tuple(c for c in COLUMNS if c != "location") + ("location",)


def export_plan(read, site="", leases=None, own=""):
    """Purpose: the address table as CSV (manual 1.10.4.9, 1.10.4.16): one site's, or every site's, one row per
             gateway, recorded address and lease nobody recorded, with the columns of plan_rows, `location` last
             (2.1.10.52: the columns before it keep their places). A cell that a
             spreadsheet would read as a formula (starting with =, +, - or @) is written with a leading apostrophe.
    Inputs:  read — read_plan's result; site — one site's name, "" for every site in read; leases — this site's
             leases (list_leases) or None; own — this site's name (whose leases they are).
    Returns: str, the CSV text with a header row.
    Fails:   never.
    Feeds:   ipam/cli/run_plan_read (export), networks_csv."""
    names = [site] if site else sorted(read.get("plans") or {})
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for name in names:
        for row in plan_rows(site_plan(read, name), leases if name == own else None):
            writer.writerow({k: (f"'{x}" if isinstance(x, str) and x[:1] in ("=", "+", "-", "@") else x)
                             for k, x in row.items()})
    return buf.getvalue()
