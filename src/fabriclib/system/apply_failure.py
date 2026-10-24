import datetime
import os

from fabriclib.common.paths import INSTALL_DIR

LOG_DIR = os.path.join(INSTALL_DIR, "archive", "apply-failed")
TAIL = 10                                  # the lines of the apply's output a job's error keeps
KEEP = 20                                  # the failed applies' logs kept, newest first


def apply_failure(output, log_dir=LOG_DIR, now=None):
    """Purpose: what a job says when its apply did not finish (decision 2.1.8.31): the last 10 lines of the apply's
             output, where its last line alone ("Error deploying configurations! Exit code 1") hid the cause, and the
             full output kept in a root-only log (0600, in a 0700 folder) whose path the message names. The oldest
             logs beyond 20 are removed.
    Inputs:  output — the apply's stdout and stderr (apply_changes' output); log_dir — where the logs go (default
             <install>/archive/apply-failed; tests give their own); now — datetime (default the UTC time).
    Returns: str, the message: "the apply did not finish:", the tail's lines, then "(the full output: <path>)"; with
             no output, saying there was none and naming no log.
    Fails:   never: a log that cannot be written is said in the message instead of its path.
    Feeds:   agent/post_pending (a page's Apply: its job's error; the settings' apply job keeps its output's last
             1200 characters already)."""
    lines = (output or "").strip().splitlines()
    if not lines:
        return "the apply did not finish (it printed nothing)"
    tail = "\n".join(lines[-TAIL:])
    stamp = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y%m%dT%H%M%S.%fZ")
    path = os.path.join(log_dir, f"apply-{stamp}.log")
    try:
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        os.chmod(log_dir, 0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(output if output.endswith("\n") else output + "\n")
        old = sorted(n for n in os.listdir(log_dir) if n.startswith("apply-") and n.endswith(".log"))[:-KEEP]
        for name in old:
            os.remove(os.path.join(log_dir, name))
        where = f"(the full output: {path})"
    except OSError as e:
        where = f"(the full output could not be kept: {e})"
    return f"the apply did not finish:\n{tail}\n{where}"
