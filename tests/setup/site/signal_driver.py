"""A real process holding a real site, for flow_test.py's signals: Ctrl-C and a lost terminal reach it as they reach setup,
run through run_setup's own handling of the site. Not a test itself. It prints READY once the site is up."""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "src"))
import fabriclib.setup.site.guided_site as gs  # noqa: E402
from fabriclib.common.ask import ask  # noqa: E402
from fabriclib.common.console import err  # noqa: E402
from fabriclib.setup.context import SetupContext  # noqa: E402
from fabriclib.setup.detach.constants import LOG  # noqa: E402
from fabriclib.setup.detach.follow_run import follow_run  # noqa: E402

gs.detect_network = lambda: {"hostname": "fabric-test", "host_ip": "127.0.0.1", "lan_cidr": "127.0.0.0/8"}
gs.open_site_port = lambda port, cidr: False


def main():
    env = os.environ
    term = sys.stdout
    ctx = SetupContext(deploy_base=env["SITE_BASE"])
    site = gs.GuidedSite(ctx, term=term, first=int(env["SITE_FIRST"]), last=int(env["SITE_LAST"]),
                         record=os.path.join(env["SITE_BASE"], "site-port"), lib_dir=env["SITE_LIB"],
                         user=int(env["SITE_USER"]) if env["SITE_USER"] else None, grace=0.1,
                         attach=os.path.join(env["SITE_BASE"], "attach.sock"))
    try:
        site.open()
        if env["SITE_STAGE"] == "question":
            os.makedirs(ctx.config_dir)                     # what the questions leave, to be taken away
            print("READY", file=term, flush=True)
            ask("test.q", "A question: ")
            return 0
        os.makedirs(ctx.config_dir)
        site.proceeding()
        open(os.path.join(ctx.config_dir, LOG), "w").close()
        gs.follow_run = lambda config_dir, out=None: follow_run(config_dir, running=lambda: True, out=out, sleep=time.sleep, interval=0.05)
        threading.Timer(0.3, lambda: print("READY", file=term, flush=True)).start()
        return site.follow(ctx.config_dir)
    except KeyboardInterrupt:
        err("interrupted")
        return 130
    finally:
        site.close()


if __name__ == "__main__":
    sys.exit(main())
