"""A simple load for the sizing measurements (manual 1.8.8.8, 2.3.8.5.1): the directory reads the console's pages make
(People, Groups, Computers and Browse at OU=people: fabric-agent's list_people, list_groups, list_machines and
browse_ou, each one call into the DC as the agent makes it), in a loop for a number of seconds, as fast as they go.
The sign-in in front of the pages (a password, TOTP and a client certificate) is left out: it costs the same at
every size. Prints each read's median and slowest time, and how many rounds ran.

    python3 size_load.py <seconds>              (as root on the fabric host; a test install only)
"""
import statistics
import sys
import time

import yaml

sys.path.insert(0, "/opt/fabric/lib")
from fabriclib.directory import held_op  # noqa: E402
from fabriclib.directory.list_machines import list_machines  # noqa: E402
from fabriclib.directory.list_people import list_people  # noqa: E402
from fabriclib.domain.browse_ou import browse_ou  # noqa: E402
from fabriclib.domain.list_groups import list_groups  # noqa: E402
from fabriclib.secrets.load_secrets import load_secrets  # noqa: E402


def main():
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        sys.exit(__doc__)
    held_op.enable()            # as fabric-agent asks (2.1.8.35)
    v = yaml.safe_load(open("/opt/fabric/config/vars.yaml"))
    secrets = load_secrets(v=v)
    reads = {"people": lambda: list_people(v, secrets=secrets), "groups": lambda: list_groups(v, secrets=secrets),
             "computers": lambda: list_machines(v, secrets=secrets),
             "browse people": lambda: browse_ou(v, ou="people", secrets=secrets)}
    took = {name: [] for name in reads}
    end, rounds = time.time() + int(sys.argv[1]), 0
    while time.time() < end:
        for name, read in reads.items():
            t0 = time.time()
            read()
            took[name].append(time.time() - t0)
        rounds += 1
    for name, times in took.items():
        print(f"{name}\tmedian {statistics.median(times):.2f} s\tslowest {max(times):.2f} s")
    print(f"{rounds} rounds")


if __name__ == "__main__":
    main()
