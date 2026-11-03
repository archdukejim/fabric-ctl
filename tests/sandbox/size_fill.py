"""Fill a test install up to a size, for the sizing model's measurements (manual 1.8.8.8, 2.3.8.5): people, computers
and groups in proportion, made the way fabric makes them, so the directory holds what an install of that size holds.
Re-runs top up (what exists is skipped), so one sandbox is measured at 5, then 100, then 1,000 people.

    python3 size_fill.py <people>              (as root on the fabric host; a test install only)

Per person: half a computer (servers and desktops alternately) and a tenth of a group; each person in one group.
Names are sz-prefixed (sz0001, szm0001, szg001) so they never meet an admin's. Prints one line per hundred made, then
"made <people> people, <machines> computers, <groups> groups in <s> s".
"""
import sys
import time

import yaml

sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.directory.add_machine import add_machine  # noqa: E402
from fabriclib.directory.create_person import create_person  # noqa: E402
from fabriclib.directory.run_op import run_op  # noqa: E402
from fabriclib.domain.create_group import create_group  # noqa: E402
from fabriclib.secrets.load_secrets import load_secrets  # noqa: E402


def _made(call, *args, **kw):
    """True when made now, False when it was there already (a re-run); other refusals propagate."""
    try:
        call(*args, **kw)
        return True
    except ValidationError as e:
        if "already" in str(e) or "taken" in str(e) or "exists" in str(e):
            return False
        raise


def main():
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        sys.exit(__doc__)
    people = int(sys.argv[1])
    v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
    secrets = load_secrets(v=v)
    groups = max(1, people // 10)
    start, count = time.time(), {"people": 0, "machines": 0, "groups": 0}
    for g in range(1, groups + 1):
        count["groups"] += _made(create_group, v, "size-test", f"szg{g:03d}", "sizing test", source="test",
                                 secrets=secrets)
    for n in range(1, people + 1):
        uid = f"sz{n:04d}"
        if _made(create_person, v, "size-test", uid, "Size", f"Test {n}", f"{uid}@size.test", source="test",
                 secrets=secrets):
            count["people"] += 1
            run_op(v, secrets, "add_group_member", {"group": f"szg{(n - 1) % groups + 1:03d}", "uid": uid})
        if n % 2 == 0:
            count["machines"] += _made(add_machine, v, "size-test", f"szm{n // 2:04d}", source="test",
                                       secrets=secrets, type="server" if n % 4 == 0 else "desktop")
        if n % 100 == 0:
            print(f"{n} people ({time.time() - start:.0f} s)", flush=True)
    print(f"made {count['people']} people, {count['machines']} computers, {count['groups']} groups in "
          f"{time.time() - start:.0f} s")


if __name__ == "__main__":
    main()
