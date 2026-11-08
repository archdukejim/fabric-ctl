import subprocess


def port_holder(port):
    """Purpose: what listens on a TCP port of this host, to say so when the site cannot have it (manual 1.3.6.7).
    Inputs:  port — int.
    Returns: str: the process as `ss` names it ("nginx (pid 12)"), or "something (ss could not say what)".
    Fails:   never (`ss` missing or failing: the second answer).
    Feeds:   setup/site/pick_port."""
    try:
        out = subprocess.run(["ss", "-H", "-ltnp", f"sport = :{port}"], capture_output=True, text=True).stdout
    except OSError:
        out = ""
    start = out.find('(("')
    if start < 0:
        return "something (ss could not say what)"
    name = out[start + 3:].split('"', 1)[0]
    pid = out.split("pid=", 1)[1].split(",", 1)[0] if "pid=" in out else "?"
    return f"{name} (pid {pid})"
