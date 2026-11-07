#!/usr/bin/env python3
"""The console's read cache against the real stack (manual 1.8.9.6, procedure 3.1.2.8), on a host with fabric installed and
the default sign-in, as root: pages through nginx and Keycloak, the real fabric-agent and the real DC. It changes the
directory (a person, a group and a grant named zz-cache-*, each removed at the end) and, with --load, runs busy loops at the
lowest priority for two minutes.

    sudo python3 read_cache.py <vars.yaml> <user> <password-file> [--load]

Prints PASS/FAIL lines; exit 1 on any FAIL. The password is read from a 0600 file and never printed."""
import argparse
import importlib.util
import os
import re
import subprocess
import sys
import time

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/opt/fabric/lib")
for name in ("page_speed.py", os.path.join("..", "host", "page_speed.py")):     # beside it, or from a checkout
    if os.path.exists(os.path.join(HERE, name)):
        spec = importlib.util.spec_from_file_location("page_speed", os.path.join(HERE, name))
        page_speed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(page_speed)
        break
from fabriclib.common.errors import ValidationError  # noqa: E402
from fabriclib.grants.grant_request import grant_request  # noqa: E402

PERSON, GROUP, GRANT = "zz-cache-person", "zz-cache-group", "zz-cache-grant"
FAILED = 0


def check(name, cond, detail=""):
    global FAILED
    FAILED += not cond
    print(f"{'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  -> {str(detail)[:400]}"), flush=True)


def sh(*cmd):
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.returncode, res.stdout + res.stderr


def samba_tool(*cmd):
    return sh("docker", "exec", "samba", "samba-tool", *cmd, "--configfile=/data/etc/smb.conf")


def counted(page, what):
    """How many the Directory's Overview counts, from its link text."""
    m = re.search(rf">{what}</a></dt>\s*<dd[^>]*>(\d+)|>{what}</dt>\s*<dd[^>]*>(\d+)", page, re.I)
    if m:
        return int(m.group(1) or m.group(2))
    m = None
    return int(m.group(1)) if m else None


def csrf_of(page):
    m = re.search(r'name="csrf" value="([^"]+)"', page)
    return m.group(1) if m else ""


def kept_age(page):
    m = re.search(r"Updated (\d+) (s|min) ago", page)
    return (int(m.group(1)) * (60 if m.group(2) == "min" else 1)) if m else None


def agent_log(since):
    return sh("journalctl", "-u", "fabric-agent", "--since", since, "--no-pager", "-o", "cat")[1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vars")
    ap.add_argument("user")
    ap.add_argument("password_file")
    ap.add_argument("--load", action="store_true", help="also the back-off under load (two minutes of busy loops)")
    args = ap.parse_args()
    v = yaml.safe_load(open(args.vars))
    with open(args.password_file) as f:
        password = f.read().strip()
    mgr = v["hostname_mgr"]
    b = page_speed.Browser(f"{v['deploy_base_dir']}/stepca/data/certs/root_ca.crt", v["ip_nginx"])
    if not page_speed.sign_in(b, mgr, args.user, password):
        raise SystemExit("not signed in")

    def get(path):
        st, _, page, took = b.go("GET", f"https://{mgr}{path}")
        return st, page, took

    def post(path, form):
        return b.go("POST", f"https://{mgr}{path}", form)

    def clean():
        sh("fabricctl", "domain", "grant", "remove", GRANT)
        samba_tool("group", "delete", GROUP)
        samba_tool("user", "delete", PERSON)

    clean()                             # what a run stopped half way left

    # ---- what the agent logged at its start: this host's class
    log = agent_log("-3 days")
    check("the agent says which class this host is", "kept reads: this host is" in log, log[-300:])
    m = re.findall(r"kept reads: this host is (\w+), (\d+) held", log)
    low = {"small": 30, "medium": 10, "large": 2}[m[-1][0]] if m else 30
    print(f"     class {m[-1] if m else '?'}; the refresh's lower limit {low} s", flush=True)

    # ---- served from what is kept
    get("/directory/sites")
    st, page, took = get("/directory/sites")
    check("a kept page says how old it is and offers Refresh", st == 200 and kept_age(page) is not None
          and 'action="/kept/refresh"' in page, page[:500])
    print(f"     /directory/sites from what is kept: {took * 1000:.0f} ms", flush=True)

    # ---- Refresh: both ways, against the real limit
    csrf = csrf_of(page)
    time.sleep(1)
    st, loc, _, _ = post("/kept/refresh", {"csrf": csrf, "read": "sites", "back": "/directory/sites"})
    check("Refresh comes back to its page", st == 303 and (loc or "").endswith("/directory/sites"), (st, loc))
    _, page, _ = get("/directory/sites")
    check("and the data is new", (kept_age(page) or 0) <= 3, kept_age(page))
    st, loc, _, _ = post("/kept/refresh", {"csrf": csrf, "read": "sites", "back": "/directory/sites"})
    _, page, _ = get("/directory/sites")
    check("negative: Refresh again too soon is refused, saying when", "it can run again in" in page, page[:800])
    time.sleep(low + 1)                 # the next Refresh of this page below may run
    st, _, page, _ = b.go("POST", f"https://{mgr}/kept/refresh", {"csrf": "wrong", "read": "sites", "back": "/"})
    check("negative: Refresh without the session's token is refused", st in (400, 403), st)

    # ---- a change made through the console: on the next load
    _, page, _ = get("/directory")
    _, page, _ = get("/directory")
    before = counted(page, "people")
    check("the Overview's count of people is on the page", before is not None, page[:1500])
    csrf = csrf_of(page) or csrf
    st, loc, added, _ = post("/directory/people/_new", {"csrf": csrf, "uid": PERSON, "email": f"{PERSON}@lan.test",
                                                       "first": "Zz", "last": "Cache"})
    check("a person held on the People page", st == 303, (st, loc))
    st, _, _, _ = post("/changes/people/apply", {"csrf": csrf})     # Apply per page: a job
    check("and applied", st == 303, st)
    for _ in range(90):
        st, review, _ = get("/changes/people")
        if st != 200 or 'http-equiv="refresh"' not in review:
            break
        time.sleep(2)
    _, page, _ = get("/directory")
    age = kept_age(page)
    check("a change through the console shows on the next load, nothing older served", counted(page, "people")
          == (before or 0) + 1 and (age is None or age < 30), (before, counted(page, "people"), age))

    # ---- a change made outside the console: within the interval, and never served as new
    get("/directory")
    _, page, _ = get("/directory")
    groups = counted(page, "groups")
    began = time.time()
    code, out = samba_tool("group", "add", GROUP)
    check("a group added with samba-tool, outside the console", code == 0, out)
    seen, age_while_old = None, None
    for _ in range(330):                # the upper limit, and a little
        _, page, _ = get("/directory")
        if counted(page, "groups") == (groups or 0) + 1:
            seen = time.time() - began
            break
        age_while_old = kept_age(page)
        time.sleep(1)
    check("it shows within the refresh, with no change applied", seen is not None, page[:500])
    print(f"     seen after {seen and round(seen)} s; the page's age just before: {age_while_old} s", flush=True)
    check("while old, the page said how old", age_while_old is not None or (seen or 99) < 3, age_while_old)

    # ---- what is kept never decides access
    def authorized():
        try:
            return grant_request(v, {"op": "authorize", "caller": PERSON, "action": "networks:plan",
                                     "target": {"site": v["site_name"]}})["by"]
        except ValidationError as e:
            return f"refused: {e}"

    grant = ["fabricctl", "domain", "grant"]
    code, out = samba_tool("group", "addmembers", GROUP, PERSON)
    check("the person is in the group", code == 0, out)
    code, out = sh(*grant, "add", GRANT, "--who", GROUP, "--networks", "plan", "--sites", v["site_name"])
    check("a grant added outside the console", code == 0, out)
    check("it gives the person the right", authorized() == f"grant {GRANT}", authorized())
    get("/directory/access")
    time.sleep(low + 1)
    csrf = csrf_of(get("/directory/access")[1]) or csrf
    post("/kept/refresh", {"csrf": csrf, "read": "domain/grants", "back": "/directory/access"})
    _, page, _ = get("/directory/access")
    check("the grants' page lists it", GRANT in page, page[:800])
    code, out = sh(*grant, "remove", GRANT)
    check("the grant removed outside the console", code == 0, out)
    right = authorized()
    _, page, _ = get("/directory/access")
    check("refused at once", right.startswith("refused"), right)
    print(f"     the page still listing it for now: {GRANT in page}; its age {kept_age(page)} s", flush=True)
    check("while the page may list it, saying how old", GRANT not in page or kept_age(page) is not None, page[:500])

    # ---- under load: refreshes back off, pages answer, nothing killed
    if args.load:
        cores = os.cpu_count() or 1
        since = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"     load before: {os.getloadavg()[0]:.1f} on {cores} cores", flush=True)
        loops = [subprocess.Popen(["nice", "-n", "19", "sh", "-c", "while :; do :; done"]) for _ in range(cores * 3)]
        slowest = 0.0
        ok = True
        try:
            end = time.time() + 120
            while time.time() < end:
                st, _, took = get("/directory/sites")
                ok = ok and st == 200
                slowest = max(slowest, took)
                time.sleep(2)
            log = agent_log("-20min")      # it may have been past the line already, as gaming-23's WSL often is
        finally:
            for loop in loops:
                loop.kill()
                loop.wait()
        check("under load every page still answered", ok, slowest)
        print(f"     under load, the slowest /directory/sites: {slowest * 1000:.0f} ms", flush=True)
        check("the refresher said it backed off", "under pressure" in log, log[-400:])
        kills = sh("journalctl", "-k", "--since", since, "--no-pager")[1]
        check("nothing was killed for memory", "Out of memory" not in kills and "oom-kill" not in kills, kills[-300:])

    # ---- leave nothing
    clean()
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
