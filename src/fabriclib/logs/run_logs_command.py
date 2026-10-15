import os
import subprocess
import sys

from fabriclib.common.ask import ask_secret
from fabriclib.common.errors import ValidationError
from fabriclib.logs.log_status import log_status

USAGE = """usage: fabricctl logs status                    log forwarding: destinations, sent, retries, errors
       fabricctl logs set-password elastic     the Elasticsearch/OpenSearch password (asked,
                                                                                      or on stdin; kept in OpenBao)"""


def run_logs_command(ctx, argv):
    """Purpose: `fabricctl logs status | set-password elastic` (design 2.1.15.1).
    Inputs:  ctx — SetupContext after load_state (vars, secrets, secrets_file, target_dir).
             argv — list of str after "logs" (default status). set-password reads the password from a hidden prompt, or
             one line of stdin when stdin is not a terminal.
    Returns: exit status: 0 success; 1 Fluent Bit not answering or a ValidationError (e.g. "empty password"); 2 usage.
    Fails:   ValidationError (including a missing CA file from deploy_fluentbit) is caught (exit 1); errors from
             save_secrets and other deploy_fluentbit errors (OSError, jinja2) propagate.
    Feeds:   fabriclib/cli.py (`fabricctl logs`).
    Notes:   the password never goes on argv; it is saved with save_secrets (the file or OpenBao), then, if Fluent Bit
             is installed, its credentials file is rewritten and the service try-restarted.
    """
    cmd, args = (argv[0], argv[1:]) if argv else ("status", [])
    try:
        if cmd == "status" and not args:
            st = log_status(ctx.vars)
            if not st["enabled"]:
                print("log forwarding is off (install_fluentbit: false)")
                return 0
            if not st["reachable"]:
                print(f"Fluent Bit is not answering: {st.get('error', '')}")
                return 1
            if not st["outputs"]:
                print("Fluent Bit runs; no destination configured (log_forwarding in vars.yaml)")
            for name, m in st["outputs"].items():
                print(f"{name:<12} sent {m['sent']}  retries {m['retries']}  errors {m['errors']}  "
                      f"dropped {m['dropped']}")
            return 0
        if cmd == "set-password" and args == ["elastic"]:
            from fabriclib.secrets.save_secrets import save_secrets
            pw = (ask_secret("logs.elastic_password", "Elasticsearch password: ") if sys.stdin.isatty()
                  else sys.stdin.readline().rstrip("\n"))
            if not pw:
                raise ValidationError("empty password")
            save_secrets({"log_elastic_password": pw}, ctx.secrets_file)
            if ctx.vars.get("install_fluentbit"):
                from fabriclib.common.jinja_env import jinja_env
                from fabriclib.logs.deploy_fluentbit import deploy_fluentbit
                deploy_fluentbit(ctx.vars, ctx.secrets, jinja_env(os.path.join(ctx.target_dir, "jinja")))
                subprocess.run(["systemctl", "try-restart", "fluentbit"], capture_output=True)
            applied = " and applied (fluentbit restarted)" if ctx.vars.get("install_fluentbit") else ""
            print("saved in OpenBao" + applied)
            return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(USAGE, file=sys.stderr)
    return 2
