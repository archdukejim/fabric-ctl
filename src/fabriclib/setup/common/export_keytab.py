import secrets
import subprocess

from fabriclib.setup.errors import SetupError

SMB_CONF = "/data/etc/smb.conf"         # the DC's configuration inside the samba container


def export_keytab(principals):
    """Purpose: the keys of the fabric host's domain account — the principals given (the account and its host/
             names: setup/common/host_identity) and nothing else, never the whole domain's (no export without
             --principal: that one holds krbtgt) — read from the samba container, for the host's /etc/krb5.keytab
             (manual 1.6.11.8).
    Inputs:  principals — list of str, e.g. ["FAB1$", "host/fab1.ad.test", "host/FAB1"].
    Returns: bytes, an MIT keytab. The copy inside the container (its /tmp, a tmpfs) is removed whatever happens.
    Fails:   SetupError when the DC does not export a principal (not running, or the account is missing).
    Feeds:   setup/join_host_domain."""
    path = f"/tmp/fabric-host-{secrets.token_hex(8)}.keytab"
    try:
        for principal in principals:
            res = subprocess.run(["docker", "exec", "samba", "samba-tool", "domain", "exportkeytab", path,
                                  f"--principal={principal}", "-s", SMB_CONF], capture_output=True, text=True)
            if res.returncode != 0:
                raise SetupError(f"the domain controller did not export {principal}'s keys (is the samba container "
                                 f"running?): {(res.stderr or res.stdout).strip()[-400:]}")
        res = subprocess.run(["docker", "exec", "samba", "cat", path], capture_output=True)
        if res.returncode != 0 or not res.stdout:
            raise SetupError("the host's keytab could not be read from the samba container")
        return res.stdout
    finally:
        subprocess.run(["docker", "exec", "samba", "rm", "-f", path], capture_output=True)
