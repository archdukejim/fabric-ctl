import subprocess

_NOT_LAN = ("lo", "docker", "br-", "veth", "virbr", "tailscale")


def host_addresses(first=None, run=subprocess.run):
    """Purpose: the IPv4 addresses a browser may reach the site at (manual 1.3.6.7): the one Guided detected first, then
             any other of this host's, without the loopback's and the containers' bridges'.
    Inputs:  first — the detected address (str or None); run — subprocess.run (tests give their own).
    Returns: list of str, without duplicates; [first] or [] when `ip` cannot say.
    Fails:   never.
    Feeds:   setup/site/guided_site."""
    try:
        out = run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True).stdout
    except OSError:
        out = ""
    found = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) > 3 and not fields[1].startswith(_NOT_LAN):
            found.append(fields[3].split("/")[0])
    return list(dict.fromkeys(([first] if first else []) + found))
