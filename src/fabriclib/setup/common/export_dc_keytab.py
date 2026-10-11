import secrets
import subprocess

from fabriclib.setup.errors import SetupError

SMB_CONF = "/data/etc/smb.conf"         # the DC's configuration inside the samba container


def _principals(v):
    """Purpose: the principals the host's keytab holds: the DC's own account and its host/ names, nothing else.
    Inputs:  v — vars: hostname (the DC's NetBIOS name, at most 15 characters: check_samba_settings), hostname_dc.
    Returns: list of str, e.g. ["FABRIC$", "host/fabric.ad.lan", "host/FABRIC"].
    Fails:   never.
    Feeds:   export_dc_keytab."""
    name = str(v.get("hostname") or "").split(".")[0].upper()
    return [f"{name}$", f"host/{v['hostname_dc']}", f"host/{name}"]


def export_dc_keytab(v):
    """Purpose: the keys of this host's domain controller account — `<HOST>$` and its host/ names only, never the
             whole domain's (no export without --principal: that one holds krbtgt) — read from the samba
             container, for the host's /etc/krb5.keytab (manual 1.6.11.8).
    Inputs:  v — vars: hostname, hostname_dc.
    Returns: bytes, an MIT keytab. The copy inside the container (its /tmp, a tmpfs) is removed whatever happens.
    Fails:   SetupError when the DC does not export a principal (not running, or the account is missing).
    Feeds:   setup/join_host_domain."""
    path = f"/tmp/fabric-host-{secrets.token_hex(8)}.keytab"
    try:
        for principal in _principals(v):
            res = subprocess.run(["docker", "exec", "samba", "samba-tool", "domain", "exportkeytab", path,
                                  f"--principal={principal}", "-s", SMB_CONF], capture_output=True, text=True)
            if res.returncode != 0:
                raise SetupError(f"the domain controller did not export {principal}'s keys (is the samba container "
                                 f"running?): {(res.stderr or res.stdout).strip()[-400:]}")
        res = subprocess.run(["docker", "exec", "samba", "cat", path], capture_output=True)
        if res.returncode != 0 or not res.stdout:
            raise SetupError("the domain controller's keytab could not be read from the samba container")
        return res.stdout
    finally:
        subprocess.run(["docker", "exec", "samba", "rm", "-f", path], capture_output=True)
