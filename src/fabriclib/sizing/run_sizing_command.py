from fabriclib.common.errors import ValidationError
from fabriclib.sizing.refresh_sizing import refresh_sizing
from fabriclib.sizing.state import read_sizing

USAGE = """usage: fabricctl sizing show       what the host is small for, if anything (also in status and doctor)
       fabricctl sizing refresh    work it out again now (the hourly timer's run)
  The numbers behind it: manual 1.8.8.8 and 2.3.8.5."""


def show_sizing(config_dir):
    """Purpose: print the sizing advice, for `fabricctl status` and `doctor` (decision 2.1.8.40): the same alerts as the
             console, from the same result, whoever dismissed them there.
    Inputs:  config_dir — fabric's config directory.
    Returns: None; a heading and two lines per alert, or one line saying all is well or not worked out yet.
    Fails:   never.
    Feeds:   cli (status, doctor), run_sizing_command (show)."""
    last = read_sizing(config_dir)
    print("\nsizing:")
    if not last["at"]:
        print("  not worked out yet (fabric-sizing.timer runs hourly, or: sudo fabricctl sizing refresh)")
    elif not last["alerts"]:
        print(f"  the host is big enough for this install (worked out {last['at']})")
    for a in last["alerts"]:
        print(f"  {'CRITICAL' if a['level'] == 'critical' else 'warn'}: {a['what']}")
        print(f"    to close it: {a['close']}")


def run_sizing_command(v, config_dir, args, container="samba"):
    """Purpose: `fabricctl sizing ...` (manual 1.8.8.8): only routes and prints.
    Inputs:  v — rendered vars; config_dir — fabric's config directory; args — list of str after `sizing` (--scheduled:
             the timer's, which says nothing when all is well); container — the DC's container.
    Returns: exit status: 0 ok, 1 refused, 2 usage.
    Fails:   OSError writing the result (propagates).
    Feeds:   cli.main."""
    scheduled = "--scheduled" in args
    rest = [a for a in args if a != "--scheduled"]
    if rest not in (["show"], ["refresh"]):
        print(USAGE)
        return 2
    if rest == ["show"]:
        show_sizing(config_dir)
        return 0
    try:
        out = refresh_sizing(v, config_dir, container=container)
    except ValidationError as e:
        print(f"refused: {e}")
        return 1
    if not scheduled:
        print(f"worked out: {out['size'].get('people', 0)} people, {out['size'].get('computers', 0)} computers, "
              f"{out['size'].get('groups', 0)} groups; {len(out['alerts'])} alert(s)")
        show_sizing(config_dir)
    return 0
